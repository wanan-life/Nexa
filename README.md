# Nexa

[English](README.en.md)

![Nexa](docs/images/nexa.svg)

## 简介

Nexa 是一个面向合法授权漏洞赏金、SRC 和内部安全测试的攻击面情报工具。名称源自 “Nexus（连接中枢）” 与 “Next（下一代）”，目标是将分散的资产、HTTP 服务、技术指纹和来源证据整理为可搜索、可复查的目标视图。

```text
资产收集 -> 标准化 -> HTTP 探测 -> 指纹入库 -> 降噪分类 -> 目标内搜索
```

Nexa 提供 CLI 与一体化 Web 管理台，支持 subfinder、OneForAll、httpx、CT、Wayback，以及可选的 FOFA、Hunter、Shodan、ZoomEye、360 Quake 查询，并内置 MCP 服务供 AI 客户端接入。项目仅用于合法授权测试，不包含自动化漏洞利用和破坏性功能。

## 安装

推荐直接从 [Releases](https://github.com/wanan-life/Nexa/releases) 下载与系统架构匹配的单文件程序。当前提供：

- `nexa-v0.2.0-macos-arm64`：Apple Silicon Mac

macOS 安装示例：

```bash
chmod +x nexa-v0.2.0-macos-arm64
xattr -d com.apple.quarantine nexa-v0.2.0-macos-arm64 2>/dev/null || true
sudo mv nexa-v0.2.0-macos-arm64 /usr/local/bin/nexa
nexa init
```

Nexa 二进制本身不需要安装 Python、Node.js 或项目源码。`nexa init` 会初始化 `~/.nexa/`，并询问是否下载当前系统对应的 subfinder、httpx 和 OneForAll；OneForAll 集成需要系统存在 Python 3。

运行数据位置：

```text
~/.nexa/data/nexa.db
~/.nexa/config/nexa.toml
~/.nexa/config/noise_rules.json
~/.nexa/tools/
```

源码开发安装方式见 [开发说明](docs/development.md)；普通使用无需克隆仓库。

## 快速使用

```bash
# 初始化数据库、配置和扫描工具
nexa init

# 添加目标并执行完整资产梳理
nexa add-target example.com --program-name "Example SRC"
nexa target 1 --scan

# 进入目标交互式查询
nexa use 1

# 一条命令启动 Web 管理台与 API
nexa web
```

Web 默认地址：`http://127.0.0.1:8000`

API 文档：`http://127.0.0.1:8000/docs`

交互式查询示例：

```text
overview
services
apps
app="Vue.js" && server="nginx"
status=200 && title="admin"
inspect 123
clean
```

交互模式支持补全：**Tab** 弹出命令与查询字段候选（裸查询 `app` ⇥ → `app=`、`status=` ⇥ → 200/301/404…；`clean st` ⇥ → `clean status=`），**→** 接受灰色行内联想（输入 `ov` 提示 `erview`）。`↑` 还支持按前缀搜索历史。

<!-- 快速使用命令截图预留位置：docs/images/nexa-command.png -->

## 扫描与提速

`nexa target <ref> --scan` 默认**跳过已探测过且未存活的主机**，只重测存活资产和上次扫描后发现的新资产（例如 jd.com 从 31051 个候选降到约 3068 个）。需要完整重扫时：

```bash
nexa target 1 --scan --rescan-dead
```

扫描期间持续输出批次与心跳（`httpx batch 3/8: 512 responses, 1200 lines, 40s elapsed`），并且**每批完成即落库**，所以某批超时或中断不会丢弃已完成的结果。并发与超时可在 `config/nexa.toml` 的 `[scan.tools]` 调整：`httpx_threads`、`httpx_rate_limit`、`httpx_request_timeout`、`httpx_retries`、`httpx_batch_size`、`httpx_timeout`。

## AI / MCP 集成

Nexa 内置 MCP（Model Context Protocol）服务，通过 stdio 把本地资产情报暴露给支持 MCP 的 AI 客户端（Claude Desktop、DSH、Cursor 等）：

```bash
# 生成客户端配置片段
nexa mcp --print-config

# 需要允许 AI 触发完整扫描时
nexa mcp --print-config --allow-scan
```

默认只注册 17 个只读工具（目标、服务、指纹、降噪、来源证据、在线测绘、CVE PoC）；会运行外部工具的 `scan_target` 需显式加 `--allow-scan`。接入方式、工具清单与查询语法见 [MCP 说明](docs/mcp.md)。

## 作者与贡献说明

- 主要作者与开发者：OpenAI Codex
- 初始想法与产品方向：wanan

用户提供了漏洞赏金资产情报系统的初始想法、实战反馈和产品方向；OpenAI Codex 负责架构设计、代码实现、文档和持续迭代。
