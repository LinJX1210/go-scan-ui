# Go Scan UI

用 Go 编写的 **IP / 端口扫描可视化工具**：在网页界面里勾选参数即可扫描，无需手敲命令。

- **原生扫描**：Go 实现的 TCP 全连接扫描，不依赖 nmap、不需要 root，支持 Banner 抓取与服务识别。
- **Nmap 模式**：把 nmap 常用参数做成选项（扫描技术、端口、主机发现、`-sV`/`-O`/`-A`、NSE 脚本、时序等），实时预览生成的命令，结果自动解析成表格。
- 单个可执行文件（前端已内嵌），复制到 Kali 即可运行。

> ⚠️ **合规声明**：本工具仅可用于你拥有或已获得**书面授权**的网络与系统。未经授权扫描他人系统可能违反《网络安全法》等法律法规，使用者自行承担全部责任。

## 功能

| 模块 | 说明 |
|---|---|
| 目标 | 单 IP、CIDR（如 `192.168.1.0/24`）、范围（`10.0.0.1-20`）、域名，可多个 |
| 原生扫描 | 端口预设（常用 / Web / 数据库 / 1-1024 / 全端口）、超时、并发、存活探测、Banner |
| Nmap 扫描技术 | `-sT` `-sS` `-sU` `-sn` `-sA` `-sW` `-sM` `-sN` `-sF` `-sX`，可叠加 UDP |
| Nmap 端口 | 默认 / `-F` / `--top-ports` / `-p` / `-p-` |
| Nmap 探测 | `-Pn` `-n` `-sV`（含强度） `-O` `-A` `--traceroute` |
| NSE 脚本 | `-sC`、常用脚本勾选、自定义脚本与 `--script-args` |
| 时序性能 | `-T0`~`-T5`、`--min-rate`、`--max-retries`、`--host-timeout` |
| 预设 | 快速扫描 / 主机发现 / 服务识别 / 全面扫描 / 漏洞脚本 |
| 结果 | 实时表格、主机卡片、原始输出、筛选、排序、导出 CSV / JSON |

## 新增界面演示（不执行扫描）

- **目录演示 / 工具演示**：浏览器内播放固定模拟数据，提供参数预览、进度、停止、结果筛选与导出。
- 演示地址固定为 `http://127.0.0.1:8080`，只是显示标签；**不会访问该地址或输入的任何地址，不调用扫描接口，不启动外部工具，不读取字典文件**。
- 参数编辑只更新预览，不影响固定模拟结果；不生成可执行工具命令。
- 结果区持续显示“模拟数据”，JSON / CSV 含 `simulated` 字段，文件名以 `demo-` 开头。
- 服务端对 `/api/scan` 的 `dir` / `tool` 模式及 `/api/tools/preview` 返回 **403**。本次发布不包含新增的真实工具执行模块。
- 原有原生 / Nmap 模式未在本次改动中扩展；切换到它们仍是原有行为，不是离线演示。

### 回归检查

```bash
node --check web/static/app.js
go test ./internal/server
```

浏览器离线模拟测试见 `tests/demo-ui.cjs`，需 Chromium；不需要启动扫描器或安装 Kali 工具。

## 在 Kali 上使用

### 方式一：在 Kali 上直接编译（推荐）

```bash
sudo apt update && sudo apt install -y golang nmap git
git clone https://github.com/LinJX1210/go-scan-ui.git
cd go-scan-ui
go build -o go-scan-ui .
sudo ./go-scan-ui          # SYN / UDP / OS 识别需要 root
```

浏览器打开 <http://127.0.0.1:8080>。

> Kali 源里的 Go 版本需 ≥ 1.22（`go version` 查看）。版本过低时用方式二。

### 方式二：在你的电脑上交叉编译，再拷到 Kali

在装有 Go 的电脑（Windows / macOS / Linux 均可）上：

```bash
# Kali 是 x86-64（绝大多数虚拟机 / PC）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o go-scan-ui-linux-amd64 .
# Kali 跑在 ARM 上（树莓派、Apple 芯片的虚拟机）
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o go-scan-ui-linux-arm64 .
```

Windows PowerShell 写法：

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"; go build -o go-scan-ui-linux-amd64 .
```

把文件拷到 Kali 后：

```bash
chmod +x go-scan-ui-linux-amd64
sudo ./go-scan-ui-linux-amd64
```

在 Kali 上运行 `uname -m` 可确认架构：`x86_64` 用 amd64，`aarch64` 用 arm64。

## 在 GoLand 中开发

1. GoLand → **Get from VCS**，填入仓库地址，或 `git clone` 后用 GoLand 打开目录。
2. 打开 `main.go`，点击 `func main` 左侧的绿色 ▶ 运行。
3. 浏览器访问 <http://127.0.0.1:8080>。
4. 修改 `web/static` 下的前端文件后需要**重新运行**（前端通过 `go:embed` 编译进程序）。
5. 运行测试：右键项目根目录 → **Run 'go test ./...'**，或命令行 `go test ./...`。

> Windows 上开发时，原生扫描可直接使用；Nmap 模式需要安装 Windows 版 nmap 并加入 PATH。

## 启动参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-addr` | `127.0.0.1:8080` | 监听地址。默认只允许本机访问 |
| `-token` | 空 | 访问令牌，也可用环境变量 `GOSCAN_TOKEN`。**监听非本机地址时必须设置** |
| `-version` | | 显示版本 |

需要从另一台电脑访问 Kali 上的界面时：

```bash
sudo ./go-scan-ui -addr 0.0.0.0:8080 -token 换成一个长随机字符串
# 访问 http://Kali的IP:8080/?token=同一个字符串
```

更安全的做法是保持默认监听，用 SSH 端口转发访问：`ssh -L 8080:127.0.0.1:8080 kali@Kali的IP`。

## 安全设计

- 默认只监听 `127.0.0.1`；监听其他地址必须设置令牌。
- nmap 通过参数数组调用，不经过 shell；目标、端口、脚本名均做白名单校验，拒绝以 `-` 开头的目标（防参数注入）。
- “额外参数”禁止 `-oN/-oX/-iL/--script/--datadir` 等读写文件或加载任意脚本的选项。
- 原生扫描单次最多展开 `/16`（65536 个主机），避免误操作扫描超大网段。
- 页面设置了 CSP、X-Frame-Options 等安全响应头；导出 CSV 时防止公式注入。

## 项目结构

```
.
├── main.go                  # 入口与启动参数
├── internal/
│   ├── scan/                # Go 原生扫描：目标/端口解析、TCP 扫描、Banner
│   ├── nmap/                # 选项 → nmap 参数、执行 nmap、解析 XML
│   └── server/              # HTTP API、任务管理、SSE 实时推送
└── web/
    ├── embed.go             # 将前端内嵌进二进制
    └── static/              # index.html / style.css / app.js
```

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/info` | nmap 是否可用、是否 root、系统架构 |
| POST | `/api/tools/preview` | 离线演示版拒绝命令生成，返回 403 |
| POST | `/api/nmap/preview` | 根据选项生成 nmap 命令 |
| POST | `/api/scan` | 启动扫描，`mode` 为 `native` 或 `nmap` |
| GET | `/api/scan/{id}/events` | SSE 实时事件流 |
| POST | `/api/scan/{id}/stop` | 停止扫描 |

## 路线图

- [ ] 集成更多 Kali 工具（masscan、whatweb、gobuster 等）
- [ ] 扫描历史保存与对比
- [ ] 原生 UDP / ICMP 探测
- [ ] 结果导出 HTML 报告

## 许可证

[MIT](LICENSE)
