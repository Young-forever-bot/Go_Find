# Young@Asset Collection

一站式资产测绘工具：**子域名收集 · 端口开放探测 · 端口服务识别 · WHOIS/备案查询**
Go 高并发后端（零第三方依赖）+ Electron 桌面控制台。内部模块名 `gofind`，应用名 Young@Asset Collection。

> ⚠️ 仅限授权安全测试使用，未经授权扫描他人系统违法。

## 功能

- **子域名收集**：DNS 字典爆破（内置 400+ 字典）/ crt.sh 证书透明度 / HackerTarget，
  自动泛解析过滤、多源去重合并、支持自定义 DNS
- **端口开放探测**：TCP Connect 扫描，目标支持 IP/域名/CIDR 混合列表，
  端口支持预设（常用/Web/全端口）与自定义区间，500+ 并发
- **端口服务识别**：Banner 抓取、HTTP(S) 探测（标题/Server/状态码）、TLS 证书信息、内置指纹库
- **WHOIS / 备案查询**：端口 43 原生 WHOIS（IANA→注册局）+ 结构化字段提取；**工信部官方接口直查**（自动识别滑块验证码，无需第三方）；多源并发竞速兜底
- **🚀 全面测绘**：一键流水线「子域名收集 → 存活探测 → 端口扫描 → 服务识别 → WHOIS/备案」，阶段进度实时可视，结果分标签展示
- **存活探测**：HTTP(S) 择优探测（状态码/标题/大小），内置 40+ 条 Web 指纹库（ThinkPHP/Shiro/Nacos/宝塔/通达OA/各类默认页…）
- **通用**：统一任务模型、SSE 实时进度、CSV/JSON 导出、任务历史持久化（重启不丢）、全表格关键字过滤

## 快速开始

**方式 0：单文件便携版（双击即用）**

直接双击 `Go_Find.exe`（84MB，打包了 Electron 前端 + Go 后端），无需安装、无需 Node/Go 环境。

**方式 1：Electron 开发模式**

```bash
cd frontend
npm install --registry=https://registry.npmmirror.com
npm start

# 重新打包单文件 exe：
set ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/
set ELECTRON_BUILDER_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/
npx electron-builder --win portable   # 产物: frontend/dist/"Young@Asset Collection.exe"
```

**方式 2：浏览器模式**

```bash
go build -ldflags "-s -w" -o bin/gofind.exe ./cmd/gofind
bin\gofind.exe -web frontend
# 打开 http://127.0.0.1:18525
```

## 命令行参数

```
gofind [-addr 127.0.0.1:18525] [-web <前端目录>] [-version]
```

## API 摘要

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/subdomain | 创建子域名收集任务 |
| POST | /api/portscan | 创建端口扫描任务 |
| POST | /api/service | 创建服务识别任务 |
| POST | /api/whois | 创建 WHOIS/备案查询任务 |
| GET | /api/tasks | 任务列表 |
| GET/DELETE | /api/tasks/{id} | 任务详情 / 取消删除 |
| GET | /api/tasks/{id}/events | SSE 实时事件流 |
| GET | /api/tasks/{id}/export?format=csv\|json | 导出结果 |

完整接口说明见 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。
