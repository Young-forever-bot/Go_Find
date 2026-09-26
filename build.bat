@echo off
setlocal
cd /d "%~dp0"
echo [1/2] 构建后端 gofind.exe ...
go build -ldflags "-s -w" -o bin\gofind.exe .\cmd\gofind
if errorlevel 1 (
  echo 后端构建失败
  exit /b 1
)
echo 后端构建完成: bin\gofind.exe
echo [2/2] 前端依赖（如未安装）
if not exist frontend\node_modules (
  pushd frontend
  call npm install --registry=https://registry.npmmirror.com
  popd
)
echo.
echo 完成！启动方式:
echo   桌面应用:  cd frontend ^&^& npm start
echo   浏览器:    bin\gofind.exe -web frontend
endlocal
