# Nexa

中文 | [English](README.en.md)

Nexa 是一个面向合法授权漏洞赏金、SRC、内部安全测试场景的攻击面情报分析平台。

Nexa 的名字源自 “Nexus（连接中枢）” 与 “Next（下一代）”：它希望成为资产、指纹、风险规则、查询语法和 AI 辅助分析之间的连接中枢，同时服务于下一代自动化安全情报工作流。

它不是一个简单把 subfinder、OneForAll、httpx 输出结果拼起来的扫描器。Nexa 的目标是把前期打点阶段大量噪声资产，转化为可入库、可搜索、可解释、可排序，并最终可交给 AI Agent 深度分析的结构化情报。

```text
资产收集 -> 标准化 -> 指纹画像 -> 目标内搜索 -> 风险评分 -> 优先级排序 -> AI 辅助分析
```

当前版本重点覆盖流水线前半段：目标管理、子域名导入、HTTP 存活探测、服务指纹入库，以及目标维度的类空间测绘查询。

## 功能特性

- 以 Target 为中心的资产数据库
- SQLite 起步，基于 SQLModel 建模
- CLI 优先的工作流，使用 Typer 和 Rich
- FastAPI 骨架，预留 API、MCP、AI Agent 集成
- 从项目内 `tools/` 目录解析外部工具
- 已集成工具适配器：
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [OneForAll](https://github.com/shmilylty/OneForAll)
- 支持导入已有子域名结果和 httpx JSONL 结果
- 支持一条命令执行目标级资产梳理
- 支持进入 target 上下文进行交互式资产查询
- 查询语法接近 FOFA / ZoomEye 风格
- 支持英文、中文分组 CLI 帮助
- 预留 JS 文件、API 端点、指纹、风险发现等数据模型

## 安全边界

Nexa 仅用于合法授权的漏洞赏金、SRC、企业内部安全测试和实验室环境。

项目不包含破坏性利用、自动化漏洞利用、鉴权绕过、批量攻击等能力。当前实现范围限定为资产收集、标准化、HTTP 探测、指纹入库和本地辅助分析。

## 安装

要求：

- Python 3.11+
- 内置工具 bootstrap 当前主要面向 macOS arm64 测试

```bash
git clone <your-repo-url> nexa
cd nexa
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nexa init
```

默认数据库位置：

```text
data/nexa.db
```

如需自定义数据库或数据目录：

```bash
export NEXA_DATABASE_URL="sqlite:////absolute/path/nexa.db"
export NEXA_DATA_DIR="/absolute/path/data"
```

## 内置工具

Nexa 默认从项目本地 `tools/` 目录调用外部工具，不依赖系统 `PATH` 进行扫描。

期望目录结构：

```text
tools/
  subfinder/
    subfinder
    config.yaml
    provider-config.yaml
  httpx/
    httpx
  OneForAll/
    oneforall.py
    .venv/
```

查看工具状态：

```bash
nexa tools
```

初始化工具：

```bash
python scripts/bootstrap_tools.py
```

当前 bootstrap 脚本会安装：

- subfinder `v2.14.0` macOS arm64 release
- httpx `v1.9.0` macOS arm64 release
- OneForAll GitHub 仓库及本地 `.venv`

如果某个内置工具缺失或运行失败，Nexa 会在 Nexa summary 中展示错误，并在允许的情况下继续执行其它阶段。

## 快速开始

添加目标：

```bash
nexa add-target jd.com --program-name "JD SRC" --scope-type in-scope
nexa targets
```

按目标 ID 执行自动梳理：

```bash
nexa target 1 --scan
```

该命令会执行目标级流水线：

1. 使用内置 subfinder 收集子域名。
2. 使用内置 OneForAll 收集子域名。
3. 标准化、去重并写入资产表。
4. 使用内置 httpx 探测 HTTP/HTTPS 存活服务。
5. 入库存活服务和 HTTP 指纹字段。

也可以按目标名执行同样的流水线：

```bash
nexa collect-target --target jd.com
```

只对库里已有资产运行 httpx：

```bash
nexa scan-http --target jd.com
```

## 导入已有结果

导入子域名列表：

```bash
nexa import-subdomains --target jd.com --file subdomains.txt --source subfinder
nexa import-subdomains --target jd.com --file oneforall.csv --source oneforall
```

导入 ProjectDiscovery httpx JSONL：

```bash
nexa import-httpx --target jd.com --file httpx.jsonl
```

## Target 内搜索

进入目标交互式工作区：

```bash
nexa use 1
nexa use jd.com
```

提示符样式：

```text
jd.com >
```

交互式提示符基于 `prompt_toolkit`，支持方向键移动光标、历史记录和行内编辑。

查询示例：

```text
app="Vue.js"
ip="127.0.0.1"
server="nginx" && status=200
app="vue" || title="admin"
cdn!="cloudflare"
alive=true
```

也可以不进入交互模式，直接执行一次查询：

```bash
nexa use 1 -q 'app="vue.js" && server="nginx"'
```

当前支持字段：

```text
app, tech, ip, host, url, title, server, cdn, waf,
status, port, scheme, source, cname, favicon, alive
```

当前支持操作符：

```text
=
!=
&&
||
```

## CLI 帮助

默认帮助为英文：

```bash
nexa --help
```

英文分组帮助：

```bash
nexa --help-en
```

中文分组帮助：

```bash
nexa --help-zh
```

## API

启动 FastAPI：

```bash
uvicorn app.main:app --reload
```

访问：

```text
http://127.0.0.1:8000/docs
```

当前 API 仍保持最小实现，主要工作流以 CLI 为主。API 层预留给后续 Web 控制台、MCP Tool 和 AI Agent 集成。

## 数据模型

当前核心模型：

- `Target`：漏洞赏金/SRC 目标、根域名、范围元数据
- `Asset`：子域名或主机、来源、IP/CNAME、存活状态
- `Service`：HTTP/HTTPS 服务、状态码、标题、Server、CDN/WAF、技术栈、响应头
- `JSFile`：前端 JavaScript 文件元数据
- `APIEndpoint`：从 JS、Swagger、HTML、日志等来源提取的 API 端点
- `Fingerprint`：结构化服务指纹
- `RiskFinding`：后续风险发现和评分结果

## 项目结构

```text
app/
  main.py              FastAPI 入口
  config.py            配置
  database.py          SQLite/SQLModel 初始化
  repositories.py      数据访问层
  query.py             Target 内查询语法
  tooling.py           内置工具解析
  models/              SQLModel 数据库模型
  schemas/             输入/输出 Schema
  collectors/          外部工具适配器和解析器
  pipelines/           目标级采集、导入、探测编排
  analyzers/           HTTP/JS/技术栈/风险分析预留
  scoring/             规则评分引擎预留
  cli/                 Typer CLI
  utils/               标准化和日志工具
scripts/
  bootstrap_tools.py   内置工具安装脚本
tools/
  README.md            内置工具目录说明
data/
  nexa.db            默认 SQLite 数据库
```

## 路线图

- 增强 httpx 字段兼容和响应头归一化
- 增加 favicon mmh3 hash 支持
- 增加 JS 抓取和 sourcemap 检测
- 从 JS、HTML、Swagger/OpenAPI、常见文档路径中提取 API 端点
- 实现规则化风险评分
- 实现 `nexa top --target ...`
- 实现高价值资产 Markdown 导出
- 增加 MCP Tool：
  - `search_assets`
  - `get_service_detail`
  - `get_js_endpoints`
  - `get_risk_findings`
  - `summarize_target`

长期设计目标是：AI Agent 不直接读取海量原始资产，而是读取经过压缩、过滤、排序后的目标级情报。

## 作者与贡献说明

- 主要作者与开发者：OpenAI Codex
- 初始想法与需求方向：wananlife

本说明用于记录该仓库的生成和开发过程：用户提出了“漏洞赏金资产情报分析系统”的初始想法和方向，OpenAI Codex 负责项目架构设计、代码实现、文档编写和迭代开发。

## 免责声明

请仅在你拥有资产所有权或明确授权测试的目标上使用本项目。你需要自行遵守相关法律法规、漏洞赏金项目规则、速率限制和测试范围约束。
