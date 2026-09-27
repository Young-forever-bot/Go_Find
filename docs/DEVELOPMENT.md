# Young@Asset Collection 开发文档

> 版本：v1.1.0 ｜ 更新日期：2026-09-27 ｜ 应用名：Young@Asset Collection（内部模块名 gofind）
> 一站式资产测绘工具：**子域名收集 + 端口开放探测 + 端口服务识别**
> 后端 Go（标准库实现，零第三方依赖）＋ 前端 Electron 桌面控制台

---

## 1. 项目概述

### 1.1 项目背景与目标

在授权渗透测试 / SRC 漏洞挖掘的信息收集阶段，需要反复执行三类动作：

1. **子域名收集** —— 从目标主域名扩展出资产边界；
2. **端口开放探测** —— 确认主机上哪些端口可达；
3. **端口服务识别** —— 判断开放端口背后运行的服务、组件与版本。

Go_Find 将三者整合为一个本地工具：Go 编写的高并发后端负责探测执行，
Electron 桌面应用作为控制台负责任务下发、实时进度展示与结果导出。

### 1.2 核心功能清单（v1.0 范围）

| 模块 | 功能点 |
|------|--------|
| 子域名收集 | DNS 字典爆破（内置 400+ 字典、支持自定义字典）、crt.sh 证书透明度查询、HackerTarget API 查询、泛解析自动检测与过滤、并发 DNS 解析、结果自动去重合并 |
| 端口开放探测 | TCP Connect 全连接扫描、目标支持 `IP / 域名 / CIDR 网段 / 混合列表`、端口支持 `单端口 / 区间 / 预设（常用、Web、全端口）/ 自定义`、goroutine 池并发、可调超时与并发数 |
| 端口服务识别 | Banner 抓取、HTTP/HTTPS 探测（状态码、标题、Server、X-Powered-By）、TLS 证书信息（主体、签发者、SAN、有效期）、内置服务指纹库（SSH/FTP/SMTP/Redis/MySQL/RDP/SMB 等）、按端口的常见服务兜底命名 |
| WHOIS / 备案 | WHOIS 原生协议查询（IANA → 注册局 referral，端口 43）、结构化字段提取（注册商/创建/到期/状态/NS）、注册域归一化（剥 www、URL、eTLD+1 近似）、ICP 备案多源查询（工信部官方直查 + 多源并发竞速 + 支持自定义源）、容错 JSON 解析 |
| 🚀 全面测绘 | 一键流水线：子域名收集 → 存活探测（HTTP/HTTPS 择优 + 40+ Web 指纹库）→ 端口扫描 → 服务识别 → WHOIS/备案；阶段状态机事件、结果按阶段打标、汇总统计 |
| 通用 | 统一任务模型（含 interrupted 恢复态）、SSE 实时进度、CSV/JSON 导出、任务历史 JSON 持久化（%APPDATA%/YoungAssetCollection，原子写入）、全部结果表格关键字过滤 |
| 通用能力 | 统一任务模型（创建/进度/日志/结果/取消）、SSE 实时事件推送、CSV / JSON 结果导出、任务历史记录 |
| 前端 | 子域名收集页、端口扫描页、服务识别页、任务中心页；实时进度条与结果表格；一键从端口扫描结果导入服务识别；后端健康状态指示 |

### 1.3 免责声明

本工具仅面向 **已获得合法授权** 的安全测试与资产测绘场景。使用者需确保自身行为符合
《网络安全法》及目标所在司法辖区的法律，未经授权对他人系统进行扫描属于违法行为。
开发者不对任何滥用行为承担责任。

---

## 2. 总体架构

### 2.1 架构图

```
┌──────────────────────────────────────────────────────────────┐
│                    Electron 桌面应用 (frontend/)              │
│  ┌────────────┐   ┌──────────────────────────────────────┐   │
│  │  main.js   │   │  renderer (index.html + renderer.js) │   │
│  │  主进程     │   │  4 个功能页 + 任务中心                 │   │
│  │  拉起/守护  │   │  fetch 下发任务 ←→ EventSource 收事件  │   │
│  │  Go 后端    │   └──────────────┬───────────────────────┘   │
│  └─────┬──────┘                  │ HTTP (127.0.0.1)          │
│        │ spawn                    │ REST + SSE               │
└────────┼──────────────────────────┼──────────────────────────┘
         ▼                          ▼
┌──────────────────────────────────────────────────────────────┐
│              Go 后端 gofind (cmd/gofind)                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ internal/api   HTTP 路由 / CORS / SSE / 导出            │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │ internal/task  任务管理器：状态机 + 事件发布 + 取消       │  │
│  ├────────────────┬───────────────────┬───────────────────┤  │
│  │ subdomain      │ portscan          │ service           │  │
│  │ DNS爆破        │ TCP Connect 扫描   │ Banner 抓取        │  │
│  │ crt.sh         │ CIDR/域名解析      │ HTTP/HTTPS 探测    │  │
│  │ HackerTarget   │ 端口规格解析       │ TLS 证书解析       │  │
│  │ 泛解析过滤      │ goroutine 池      │ 指纹匹配           │  │
│  └────────────────┴───────────────────┴───────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ whois  WHOIS(端口43: IANA→注册局) + ICP备案(多源API链)   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
         │                │                  │
         ▼                ▼                  ▼
      DNS 服务器      目标主机:端口       目标 HTTP 服务
```

### 2.2 架构决策记录

| 决策 | 选择 | 理由 |
|------|------|------|
| 前后端通信 | 本地 HTTP REST + SSE | Electron 渲染进程与 Go 进程解耦；后端也可独立用浏览器访问（`-web` 参数）；调试方便 |
| 后端依赖 | 仅 Go 标准库 | DNS 用 `net.Resolver`、扫描用 `net.Dialer`，无 CGO、无第三方包，交叉编译零负担 |
| 实时推送 | SSE（而非 WebSocket） | 单向推送足够；浏览器原生 `EventSource` 自带重连；实现简单 |
| 结果传输 | 逐条推送 + 任务快照 | 扫描结果可达数万条，逐条流式渲染避免一次性大 JSON 阻塞 UI |
| 并发模型 | 固定大小 goroutine 池 + channel | 精确控制对目标系统的压力，避免无上限 goroutine |
| 任务存储 | 内存 | 工具型单机场景，重启即清空，简化实现；导出落盘交给用户 |

---

## 3. 技术选型

| 层 | 技术 | 版本要求 |
|----|------|----------|
| 后端语言 | Go | ≥ 1.22（使用了 1.22 的 `ServeMux` 路径参数路由） |
| 后端 HTTP | `net/http` | 标准库 |
| DNS 解析 | `net.Resolver`（支持自定义 DNS 服务器） | 标准库 |
| 并发 | `goroutine` + `sync` + `atomic` + `context` | 标准库 |
| 前端框架 | Electron（纯 HTML/CSS/JS，无打包器） | ≥ 33，Node ≥ 18 |
| 结果导出 | CSV（UTF-8 BOM，Excel 友好）/ JSON | 自实现 |

---

## 4. 目录结构

```
Go_Find/
├── README.md                     # 项目简介与快速开始
├── docs/
│   └── DEVELOPMENT.md            # 本开发文档
├── go.mod                        # Go 模块定义 (module gofind)
├── build.bat / build.sh          # 一键构建脚本
├── .gitignore
├── bin/                          # 构建产物 gofind.exe
├── cmd/
│   └── gofind/
│       └── main.go               # 入口：解析参数、启动 HTTP 服务
└── internal/
    ├── model/
    │   └── model.go              # 全局数据结构（结果/事件/进度/日志）
    ├── task/
    │   └── manager.go            # 任务管理器：创建/进度/结果/日志/订阅/取消
    ├── subdomain/
    │   ├── subdomain.go          # 子域名收集引擎
    │   └── data/
    │       └── subdomains.txt    # 内置爆破字典（go:embed）
    ├── portscan/
    │   ├── portscan.go           # 端口扫描引擎 + 目标解析(CIDR/域名)
    │   └── ports.go              # 端口规格解析与预设端口表
    ├── service/
    │   ├── service.go            # 服务识别引擎（探测状态机）
    │   └── fingerprint.go        # 指纹库 + 常见端口名表
    ├── probe/
    │   └── probe.go              # Web 存活探测 + 指纹识别
    ├── pipeline/
    │   └── pipeline.go           # 全面测绘五阶段流水线
    ├── whois/
    │   ├── whois.go              # WHOIS 协议查询 + ICP 多源竞速
    │   └── miit.go               # 工信部官方直查（滑块验证码自动识别）
    └── api/
        ├── server.go             # 路由注册 + CORS 中间件
        ├── handlers.go           # REST 处理器
        ├── runners.go            # 任务执行器（包一层 emit 回调）
        ├── sse.go                # SSE 事件流处理
        └── export.go             # CSV/JSON 导出
frontend/                         # Electron 应用
├── package.json
├── main.js                       # Electron 主进程：拉起 Go 后端、创建窗口
├── preload.js                    # contextBridge 暴露 API 地址
├── index.html
├── renderer.js                   # 页面逻辑（fetch + EventSource）
└── styles.css
```

---

## 5. 开发环境准备

```bash
# 1. Go ≥ 1.22
go version

# 2. Node.js ≥ 18 与 npm（用于 Electron）
node -v && npm -v

# 3. 构建后端（在 Go_Find 目录）
go build -ldflags "-s -w" -o bin/gofind.exe ./cmd/gofind

# 4. 安装前端依赖并启动（国内可先设置 Electron 镜像）
cd frontend
npm install --registry=https://registry.npmmirror.com
npm start
```

> Electron 二进制下载慢时：`set ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/`（Windows CMD）
> 或 `export ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/`（Git Bash）。

---

## 6. 后端详细设计

### 6.1 分层与数据流

```
HTTP Handler ──创建任务──▶ task.Manager ──▶ goroutine 执行 runner
     ▲                                        │
     │            emit(Event) 回调             │
     │                                        ▼
     │                          ┌── progress → mgr.SetProgress ─┐
     │                          ├── log      → mgr.AddLog      ├─▶ publish → SSE 订阅者
     │                          └── result   → mgr.AddResult    ┘
     └── GET /api/tasks/{id} 随时可读快照
```

三大引擎（subdomain / portscan / service）只暴露一个统一签名，与业务层完全解耦：

```go
type Options struct{ /* 各模块参数 */ }
type Emitter func(model.Event)          // 向任务管道发事件
func Run(ctx context.Context, o Options, emit Emitter) error
```

`ctx` 取消即任务中止（前端「取消」按钮 → `DELETE /api/tasks/{id}` → `context.CancelFunc`）。

### 6.2 数据模型（internal/model）

```go
type Progress struct { Done, Total int }

type LogEntry struct { Time time.Time; Level string /* info|warn|error */; Msg string }

type Event struct { Type string /* progress|log|result|done */; Data any }

// —— 三类结果 ——
type SubdomainResult struct { Subdomain string; IPs []string; Source string }
type PortResult       struct { Host, IP string; Port int; Status string }
type ServiceResult    struct {
    Host, IP string; Port int
    Service, Version, Banner string
    HTTP *HTTPInfo   // StatusCode/Title/Server/PoweredBy/URL
    TLS  *TLSInfo    // Subject/Issuer/SANs/NotAfter
}
```

### 6.3 任务管理器（internal/task）

- **Task**：`ID / Type / Status / Params / Progress / Results[] / Logs[] / Error / CreatedAt / FinishedAt`
- **状态机**：`running → done | error | canceled`（终态不可逆）
- **ID 生成**：`{UnixMilli}-{自增序号}`，进程内唯一
- **事件发布**：每个任务可有多个 SSE 订阅者；发布为非阻塞写（订阅慢不拖垮扫描）
- **并发安全**：全局 `sync.RWMutex`；读取快照时深拷贝 Results/Logs 切片（截断 cap，避免 append 写穿共享底层数组）

### 6.4 子域名收集模块（internal/subdomain）

**执行流程：**

```
校验域名 → 检测泛解析 → [crt.sh] → [HackerTarget] → [DNS 字典爆破]
        → 对被动收集到的无 IP 结果补一次解析 → 过滤泛解析 → 去重合并 → 输出
```

1. **泛解析检测**：向 `随机10位串.域名` 发起 3 次 DNS 查询，任意一次成功解析即判定泛解析，
   收集这些随机域名的 IP 集合 `wildIPs`；后续结果若 **全部 IP 都落在 wildIPs 中** 则丢弃。
2. **crt.sh**：`GET https://crt.sh/?q=%25.<domain>&output=json`，取 `name_value`
   字段（可能多行、含 `*.` 通配符），清洗后只保留 `*.domain` 的子域。超时 25s，失败降级为警告。
3. **HackerTarget**：`GET https://api.hackertarget.com/hostsearch/?q=<domain>`，
   逐行解析 `sub,ip`；若返回配额超限文本则告警跳过。
4. **DNS 字典爆破**：字典 = 请求传入 `wordlist` 或内置 `data/subdomains.txt`（go:embed 嵌入）。
   goroutine 池（默认并发 50）逐个 `LookupHost(sub.domain)`，解析成功即收录。
5. **自定义 DNS**：`Options.DNSServer` 非空时构造 `net.Resolver{PreferGo: true, Dial: → dns:53}`，
   所有查询走指定服务器（可用于内网 DNS / 字典专用解析器）。
6. **合并规则**：以子域名为 key；来源多选一合并为 `brute,crt.sh,hackertarget` 逗号串；IP 取首次解析结果。

### 6.5 端口开放探测模块（internal/portscan）

**目标解析**（`resolveTargets`）：
- 输入支持逗号/空格/换行分隔的混合列表：`192.168.1.1, scanme.org, 10.0.0.0/24`
- CIDR：`net.ParseCIDR` 后按掩码展开全部地址（**上限 /112 规模 65536**，超出直接报错防误扫全网）；
- 域名：`LookupHost` 展开为全部 A 记录；解析失败记录警告日志并跳过；
- 结果按 `host/ip` 去重。

**端口解析**（`ParsePorts`）：
- 预设：`common`（约 500 个常用端口）、`web`（约 60 个 Web 常见端口）、`full`（1-65535）；
- 自定义：`80,443,8000-8100` 任意组合；去重升序；总数上限 10,000,000（主机×端口）。

**扫描内核**：TCP Connect 扫描 —— `net.Dialer{Timeout}.DialContext("tcp", ip:port)`，
成功即端口开放（立即 `Close()`）。固定 worker 池（默认 500，上限 5000）+ 无缓冲 channel 分发任务；
进度按 `total/200` 步长节流推送，避免 SSE 洪泛。

### 6.6 端口服务识别模块（internal/service）

对每个 `host:port` 执行如下探测状态机：

```
TCP 连接并读 Banner(2s)
 ├─ Banner 含 "HTTP/" ──────▶ HTTP 明文探测（失败再试 HTTPS）
 ├─ Banner 非空 ────────────▶ 指纹库匹配 → 命中: service=xxx(+version)
 │                                           └ 未命中: service=knownPortName(port)
 └─ Banner 为空（HTTP 服务等请求才回包）─▶ 依次尝试:
        ① HTTP 明文探测  ② HTTPS/TLS 探测  ③ 发送 "\r\n" 再读 Banner
        全部失败 → service = knownPortName(port)
```

- **HTTP 探测**：`GET /`，禁止重定向跟随（记录 302 本身），抓 `状态码 / Server / X-Powered-By / <title>`；
  body 截断 256KB，标题做 HTML 反转义与压缩空白。
- **HTTPS 探测**：`tls.DialWithDialer`（`InsecureSkipVerify`，域名目标自动带 SNI），
  先取证书信息（Subject/Issuer/SAN/NotAfter），再发 HTTPS 请求取 HTTP 信息；
  TLS 成功但 HTTP 失败时仍保留 `service=https + TLSInfo`。
- **指纹库**（`fingerprint.go`）：正则表按序匹配，含
  OpenSSH/FTP(vsftpd、ProFTPD…)/SMTP(Postfix、Exim…)/Redis/MySQL/PostgreSQL/MongoDB/
  Memcached/Elasticsearch/IMAP/POP3/RDP/SMB/VNC/Web 服务器(nginx、Apache、IIS、Tomcat…)；
  表项形如 `{正则, 服务名, 版本捕获组}`。
- **端口名兜底**：内置约 70 个常见端口 → 服务名映射（3389→rdp、6379→redis、8080→http-proxy…）。
- **Banner 清洗**：非打印字符转 `.`，空白折叠，截断 300 字符。

### 6.7 WHOIS / 备案查询模块（internal/whois）

**WHOIS 原生协议查询**（端口 43）：

```
whois.iana.org:43 查询域名 → 解析 "refer:"/whois server 字段
  → 连接注册局 whois 服务器（如 whois.verisign-grs.com / whois.cnnic.cn）再查一次
  → 返回注册局原始记录
```

- **结构化提取**：正则兼容 VeriSign/CNNIC 等格式 —— `Registrar`、
  `Creation Date/Registration Time`、`Registry Expiry Date/Expiration Time`、
  `Domain Status`、`Name Server/nserver`（去重最多 8 条）。
- **注册域归一化**：剥协议头/路径/端口/`www.`，用内置二级公共后缀表（com.cn、co.uk 等 30+）
  做 eTLD+1 近似 —— `www.pan.baidu.com` → `baidu.com`，`a.example.co.uk` → `example.co.uk`。
- 原始输出随结果保留（截断 4000 字符），导出 JSON 可见全文。

**ICP 备案查询（工信部官方直查为主源，多源并发竞速）**：

主源为工信部官方接口直查（`hlwicpfwc.miit.gov.cn`，零第三方依赖）：

```
① POST auth:  authKey = md5("testtest" + 秒级时间戳), timeStamp = 秒级时间戳 → token
② POST image/getCheckImagePoint → uuid + 滑块拼图背景图(base64 PNG)
③ 缺口定位: 解码 PNG → 灰度化 → 积分图方差扫描 → 方差≈0 的纯色窗口即缺口 → 缺口左上角 x
④ POST image/checkImage {key: uuid, value: "<缺口x>"} → sign
⑤ POST icpAbbreviateInfo/queryByCondition {unitName: 域名} (headers: uuid + sign) → 备案记录
```

- 已实测：`baidu.com → 北京百度网讯科技有限公司/企业/京ICP证030173号-1`、
  `shu.edu.cn → 上海大学/事业单位/沪ICP备09014157号-1`。
- 官方源明确返回"无备案记录"时，立即输出权威结论 `工信部备案库无该域名的备案记录`。
- 查询端点偶发 WAF 403（频控）时自动间隔 2s 重试一次。

**多源并发竞速**：官方源与内置 3 个 HTTP 聚合源、用户自定义源**同时并发**请求，
任一返回有效备案信息即胜出，总耗时 ≈ 最快的那个源，而非串行叠加。
全部失败时聚合各源错误信息（截断 300 字符）写入结果的 `icp_error` 字段。

- **容错解析**：不绑定固定响应结构，递归遍历 JSON 树，按常见键名（name/unit/company、
  icp/beian、type/nature、site/domain、time/audit_time…）匹配字段；
  备案号需命中 `汉字ICP…号` 正则方为有效。
- 公益聚合源可用性波动大，自定义 `icp_api`（模板含 `{domain}` 占位符，返回 JSON）
  可接入自建/商用接口；工信部源不依赖任何第三方，通常已足够。

---

## 7. HTTP API 文档

后端默认监听 `http://127.0.0.1:18525`（`-addr` 可改）。所有请求/响应均为 JSON（UTF-8）。
响应统一结构：成功直接返回数据；失败返回 `{"error": "..."}` + 对应 HTTP 状态码。

### 7.1 健康检查

```
GET /api/health
→ 200 {"status":"ok","version":"1.0.0","time":"2026-09-26T10:00:00+08:00"}
```

### 7.2 创建任务

**子域名收集**

```
POST /api/subdomain
{
  "domain": "example.com",              // 必填，主域名
  "methods": ["brute","crtsh","hackertarget"],  // 可选，默认全部
  "wordlist": ["www","mail"],           // 可选，自定义字典（覆盖内置）
  "concurrency": 50,                    // 可选，DNS 并发，默认 50
  "dns": "223.5.5.5",                   // 可选，自定义 DNS 服务器
  "timeout_ms": 3000                    // 可选，单次 DNS 超时，默认 3000
}
→ 200 {"task_id": "1727330400000-1"}
```

**端口开放探测**

```
POST /api/portscan
{
  "targets": "192.168.1.1, scanme.org, 10.0.0.0/24",  // 必填，混合目标列表
  "ports": "common",                    // common|web|full 或 "80,443,8000-8100"
  "timeout_ms": 1000,                   // 可选，单端口连接超时，默认 1000
  "workers": 500                        // 可选，并发数，默认 500（上限 5000）
}
→ 200 {"task_id": "1727330400000-2"}
```

**端口服务识别**

```
POST /api/service
{
  "targets": ["1.2.3.4:80", "scanme.org:22"],  // 必填，host:port 列表
  "timeout_ms": 5000,                   // 可选，默认 5000
  "workers": 50                         // 可选，默认 50
}
→ 200 {"task_id": "1727330400000-3"}
```

**WHOIS / 备案查询**

```
POST /api/pipeline
{
  "domain": "example.com",              // 必填，主域名
  "methods": ["brute","crtsh","hackertarget"],  // 子域名收集方式
  "wordlist": ["www","mail"],           // 可选自定义字典
  "concurrency": 50, "workers": 500,    // DNS / 端口并发
  "ports": "web",                       // 端口预设
  "whois": true,                        // 是否查询 WHOIS/备案
  "icp_api": ""                         // 自定义备案源
}
→ 200 {"task_id": "..."}  // SSE 中会推送 type:"stage" 阶段事件

POST /api/whois
{
  "domains": ["baidu.com", "example.org"],  // 必填，每行/逗号分隔，支持 www、URL 自动归一化
  "whois": true,                        // 可选，默认 true，WHOIS 注册信息
  "icp": true,                          // 可选，默认 true，ICP 备案查询
  "timeout_ms": 10000,                  // 可选，单次查询超时，默认 10000
  "workers": 20,                        // 可选，默认 20
  "icp_api": ""                         // 可选，自定义备案 API（含 {domain} 占位符，返回 JSON）
}
→ 200 {"task_id": "1727330400000-4"}
```

### 7.3 任务查询与管理

```
GET    /api/tasks             → 200 [{"id","type","status","progress",...}, ...]  按创建时间倒序
GET    /api/tasks/{id}        → 200 完整任务快照（含 results 与 logs）
DELETE /api/tasks/{id}        → 200 {"ok":true}   取消运行中任务 / 删除历史任务
GET    /api/tasks/{id}/events → SSE 事件流（见 7.4）
GET    /api/tasks/{id}/export?format=csv|json
                              → 文件下载（CSV 带 UTF-8 BOM，Excel 直接打开不乱码）
```

任务对象结构：

```json
{
  "id": "1727330400000-2",
  "type": "portscan",            // subdomain | portscan | service
  "status": "running",           // running | done | error | canceled
  "params": { "...": "创建时请求体" },
  "progress": { "done": 320, "total": 1000 },
  "results": [ { "host": "1.2.3.4", "ip": "1.2.3.4", "port": 443, "status": "open" } ],
  "logs":   [ { "time": "...", "level": "info", "msg": "..." } ],
  "error": "",
  "created_at": "...", "finished_at": null
}
```

### 7.4 SSE 事件协议

订阅后**先收到一条 `snapshot`**（当前全量快照，断线重连后据此恢复），随后是增量事件：

```
event 流 data 行（JSON）:
{"task_id":"...","type":"snapshot","data":{...任务快照...}}
{"task_id":"...","type":"progress","data":{"done":320,"total":1000}}
{"task_id":"...","type":"log","data":{"time":"...","level":"info","msg":"..."}}
{"task_id":"...","type":"result","data":{...SubdomainResult|PortResult|ServiceResult...}}
{"task_id":"...","type":"done","data":{"status":"done","error":""}}   ← 终态，客户端应关闭连接
```

### 7.5 curl 自测示例

```bash
# 健康
curl http://127.0.0.1:18525/api/health

# 扫描本机常用端口
curl -X POST http://127.0.0.1:18525/api/portscan \
  -H "Content-Type: application/json" \
  -d '{"targets":"127.0.0.1","ports":"1-20000","timeout_ms":300,"workers":1000}'

# 识别上面扫到的开放端口
curl -X POST http://127.0.0.1:18525/api/service \
  -H "Content-Type: application/json" \
  -d '{"targets":["127.0.0.1:18525"]}'

# 子域名收集（对外网域名，需要本机可访问 DNS/互联网）
curl -X POST http://127.0.0.1:18525/api/subdomain \
  -H "Content-Type: application/json" -d '{"domain":"example.com"}'

# 订阅事件流
curl -N http://127.0.0.1:18525/api/tasks/<task_id>/events
```

---

## 8. 前端详细设计（Electron）

### 8.1 进程模型

- **主进程 `main.js`**：
  1. 启动时查找后端二进制：环境变量 `GOFIND_BACKEND` 或 `../bin/gofind.exe`（按平台适配）；
  2. 找到则 `spawn` 拉起并轮询 `/api/health` 等待就绪；找不到则仅告警（允许连接外部已启动的后端）；
  3. 创建 1280×800 窗口，加载 `index.html`；应用退出时 `kill` 后端子进程。
- **预加载 `preload.js`**：`contextBridge` 暴露 `window.gofind = { apiBase, platform, version }`
  （`contextIsolation: true`，渲染进程不直接接触 Node 能力）。
- **渲染进程 `renderer.js`**：纯原生 JS。API 地址规则：`file://` 协议下用 `window.gofind.apiBase`；
  若页面由后端直接托管（`http://127.0.0.1:18525`）则用同源。

### 8.2 页面结构

| 页面 | 表单控件 | 结果区 |
|------|----------|--------|
| 子域名收集 | 域名输入框；brute/crt.sh/hackertarget 复选框；并发、自定义 DNS、自定义字典(多行文本) | 表格(子域名/IP/来源) + 进度条 + 日志 + 导出 |
| 端口探测 | 目标多行文本；端口预设下拉(常用/Web/全/自定义)+自定义输入；超时、并发 | 表格(主机/IP/端口/状态) + 进度条 + 导出 |
| 服务识别 | `host:port` 多行文本；超时、并发；**「从端口扫描任务导入」按钮** | 表格(主机/IP/端口/服务/版本/标题/Server/Banner) + 导出 |
| WHOIS/备案 | 域名多行文本；WHOIS 与 ICP 复选框；超时；自定义备案 API 输入框 | 表格(域名/注册商/创建/到期/DNS/备案主体/备案号/备注) + 导出 |
| 任务中心 | 刷新按钮 | 全部任务列表(类型/状态徽章/进度/结果数/创建时间/查看/取消/导出)；详情表格 |

**交互要点**：
- 每个功能页有独立任务状态（进行中新任务时输入禁用）；
- `EventSource` 收到 `done` 事件即关闭连接；`snapshot` 事件用于恢复（刷新页面后重连不丢数据）；
- 顶栏右侧圆点每 5s 轮询 `/api/health`，绿=后端在线，红=离线；
- 服务识别页可下拉选择历史端口扫描任务，自动把其中 `open` 结果填充为 `host:port` 列表。

---

## 9. 构建与打包

### 9.1 开发运行

```bash
# 方式 A：纯浏览器访问（开发调试最方便）
go build -o bin/gofind.exe ./cmd/gofind
./bin/gofind.exe -web frontend        # 打开 http://127.0.0.1:18525

# 方式 B：Electron 桌面应用
cd frontend && npm install && npm start   # main.js 自动拉起 ../bin/gofind.exe
```

### 9.2 命令行参数

```
gofind [-addr 127.0.0.1:18525] [-web frontend目录] [-version]
```

### 9.3 打包发布（已验证可用）

```bash
# 后端交叉编译（产物 bin/gofind.exe 会随应用一起打包）
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/gofind.exe ./cmd/gofind

# Electron 单文件便携版（frontend/package.json 已配置 portable target）
cd frontend
npm install electron-builder --save-dev --registry=https://registry.npmmirror.com

# 国内网络需设置镜像，并跳过代码签名（未购买证书）
set ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/
set ELECTRON_BUILDER_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/
set CSC_IDENTITY_AUTO_DISCOVERY=false
npx electron-builder --win portable
# 产物: frontend/dist/Go_Find.exe (~84MB, 双击即用)
# 打包配置要点: extraResources 把 ../bin 打进 resources/bin；
# main.js 的 backendBinary() 优先从 process.resourcesPath/bin 查找后端。
```

---

## 10. 测试计划

| 编号 | 用例 | 预期 |
|------|------|------|
| T1 | `go build ./... && go vet ./...` | 编译与静态检查通过 |
| T2 | 启动后端，`GET /api/health` | 200，status=ok |
| T3 | portscan 127.0.0.1 `1-20000` | 检出后端自身监听端口 18525 为 open |
| T4 | service 127.0.0.1:18525 | service=http，能取到状态码与页面标题 |
| T5 | subdomain 域名 `example.com`（需外网） | crt.sh/hackertarget/brute 结果合并、来源标注正确 |
| T6 | subdomain 传入泛解析域名（如部分通配站点） | 泛解析结果被过滤并输出 warn 日志 |
| T7 | portscan 目标含不可解析域名 | 输出 warn 日志并继续扫描其余目标 |
| T8 | 任务进行中 `DELETE /api/tasks/{id}` | 状态变更为 canceled，SSE 推送 done 事件 |
| T9 | export format=csv 用 Excel 打开 | 中文不乱码（BOM），表头正确 |
| T10 | Electron `npm start` | 自动拉起（或复用已运行的）后端，窗口展示，任务实时刷新 |
| T11 | whois 查询 `baidu.com` / `example.org` | 经 IANA→注册局链路返回注册商/日期/NS；`www.baidu.com` 归一化为 `baidu.com` |
| T12 | ICP 查询 `baidu.com` / `shu.edu.cn` | 工信部官方源返回备案号（沪ICP备09014157号-1 等）；未备案域名输出"工信部备案库无该域名的备案记录" |

---

## 11. Roadmap（后续可扩展）

- 子域名：集成 SecurityTrails / FOFA / Hunter / ZoomEye API；DNS 记录类型枚举（MX/NS/TXT）；子域名存活 HTTP 探测
- 端口：SYN 扫描（需 raw socket/npcap）；服务识别结果回填端口扫描任务联动
- 服务：Web 指纹库（指纹哈希/关键路径）、截图、WAF 识别、nuclei PoC 联动
- 工程：任务持久化（SQLite）、扫描报告（HTML/PDF）、国际化、自动更新
