# Nexa

[English](README.en.md)

## 简介
![nexa](docs/images/nexa.svg)

Nexa 是一个面向合法授权漏洞赏金、SRC、内部安全测试场景的攻击面情报分析平台。

Nexa 的名字源自 “Nexus（连接中枢）” 与 “Next（下一代）”：它希望成为资产、指纹、风险规则、查询语法和 AI 辅助分析之间的连接中枢，同时服务于下一代自动化安全情报工作流。

它不是简单拼接 subfinder、OneForAll、httpx 输出结果的扫描器。Nexa 的目标是把前期打点阶段大量噪声资产，转化为可入库、可搜索、可解释、可排序，并最终可交给 AI Agent 深度分析的结构化情报。

```text
资产收集 -> 标准化 -> 指纹画像 -> 目标内搜索 -> 风险评分 -> 优先级排序 -> AI 辅助分析
```

当前版本重点支持：

- 目标管理
- 子域名收集与导入
- HTTP/HTTPS 存活探测
- 服务指纹入库
- target 维度的交互式资产查询
- 类 FOFA / ZoomEye 的本地查询语法

本项目仅用于合法授权测试，不包含破坏性利用、自动化漏洞利用、鉴权绕过或批量攻击逻辑。

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

初始化内置工具：

```bash
python scripts/bootstrap_tools.py
```

查看内置工具状态：

```bash
nexa tools
```

默认数据库位置：

```text
data/nexa.db
```

扫描工具默认开关位于：

```text
config/scan.toml
```

示例：

```toml
[tools]
subfinder = true
oneforall = true
httpx = true
```

## 快速使用


添加目标：

```bash
nexa add-target jd.com --program-name "JD SRC" --scope-type in-scope
nexa targets
```

多个一级域名建议分别创建 Target，并用同一个 `program_name` 归类：

```bash
nexa add-target aaa.com --program-name "Example SRC"
nexa add-target bbb.com --program-name "Example SRC"
```

执行目标级自动梳理：

```bash
nexa target 1 --scan
```

也可以按目标名执行：

```bash
nexa collect-target --target jd.com
```

只对已有资产重新运行 httpx：

```bash
nexa scan-http --target jd.com
```

重复扫描或导入会自动增量更新，不需要删除整个 Target：

```bash
nexa target 1 --scan
nexa import-subdomains --target jd.com --file new-subdomains.txt --source subfinder
nexa import-httpx --target jd.com --file new-httpx.jsonl
```

进入 target 交互式查询：

```bash
nexa use 1
nexa use jd.com
```

查询示例：

```text
app="Vue.js"
ip="127.0.0.1"
server="nginx" && status=200
app="vue" || title="admin"
cdn!="cloudflare"
alive=true
```

非交互查询：

```bash
nexa use 1 -q 'app="vue.js" && server="nginx"'
```

删除目标：

```bash
nexa delete-target jd.com
nexa del-target jd.com
```


## 作者与贡献说明

- 主要作者与开发者：OpenAI Codex
- 初始想法与需求方向：用户提供

本说明用于记录该仓库的生成和开发过程：用户提出了“漏洞赏金资产情报分析系统”的初始想法和方向，OpenAI Codex 负责项目架构设计、代码实现、文档编写和迭代开发。

