# Nexa

[English](README.en.md)

## 简介
![nexa](docs/images/nexa.svg)

Nexa 是一个面向合法授权漏洞赏金、SRC、内部安全测试场景的前期目标踩点工具。

Nexa 的名字源自 “Nexus（连接中枢）” 与 “Next（下一代）”：它希望成为目标、资产、指纹、空间测绘和本地查询之间的轻量连接中枢。

它不是简单拼接 subfinder、OneForAll、httpx 输出结果的扫描器。Nexa 的目标是把前期打点阶段大量噪声资产，转化为可入库、可搜索、可复查的结构化资产视图。

```text
资产收集 -> 标准化 -> 存活探测 -> 指纹入库 -> 目标内搜索 -> 导出复查
```

当前版本重点支持：

- 目标管理
- 子域名收集
- HTTP/HTTPS 存活探测
- 服务指纹入库
- target 维度的交互式资产查询
- 类 FOFA / ZoomEye 的本地查询语法
- FOFA、Hunter、Shodan、ZoomEye 在线测绘接口预留

本项目仅用于合法授权测试，不包含破坏性利用、自动化漏洞利用、鉴权绕过或批量攻击逻辑。

## 安装

要求：

- Python 3.11+
- 内置工具 bootstrap 会按当前 OS/CPU 架构下载对应工具包

```bash
git clone <your-repo-url> nexa
cd nexa
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nexa init
```

`nexa init` 会初始化数据库，并在发现 subfinder、httpx、OneForAll 缺失时询问是否下载。也可以跳过确认：

```bash
nexa init --bootstrap-tools
```

查看内置工具状态：

```bash
nexa tools
```

默认数据库位置：

```text
data/nexa.db
```

统一配置文件：

```text
config/nexa.toml
```

可从模板复制：

```bash
cp config/nexa.example.toml config/nexa.toml
```

示例：

```toml
[scan.tools]
subfinder = true
oneforall = true
httpx = true

[scan.online]
providers = true
limit = 30

[providers.hunter_qianxin]
enabled = false
api_key = ""
```

`providers.*.enabled = true` 后，`nexa target 1 --scan` 会自动调用已启用的线上测绘引擎并入库去重。

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

重复扫描会自动增量更新，不需要删除整个 Target：

```bash
nexa target 1 --scan
nexa scan-http --target jd.com
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

在线测绘查询需要先在 `config/nexa.toml` 启用 provider 并配置 API Key：

```bash
nexa online-search 'domain.suffix="example.com"' --provider fofa --limit 30
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
