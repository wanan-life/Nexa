# Nexa MCP Server

Nexa 内置一个 [MCP（Model Context Protocol）](https://modelcontextprotocol.io) 服务，通过 **stdio** 把本地资产情报库暴露给支持 MCP 的 AI 客户端（Claude Desktop、DSH、Cursor 等）。AI 可以直接查询目标、服务、指纹、降噪结果和来源证据，无需手工导出数据。

- 传输：stdio（由客户端拉起 `nexa mcp` 子进程，JSON-RPC 走 stdin/stdout）
- 能力：tools（17 个只读工具，外加可选的 `scan_target`）
- 默认只读，不监听任何网络端口，不包含漏洞利用功能

## 前置条件

- 已执行过 `nexa init`
- 目标数据已扫描（`nexa target <ref> --scan`，或在 Web 管理台点「开始扫描」）

## 快速开始

生成客户端配置片段：

```bash
nexa mcp --print-config
```

输出（命令路径按当前安装自动解析）：

```json
{
  "mcpServers": {
    "nexa": {
      "command": "/usr/local/bin/nexa",
      "args": ["mcp"]
    }
  }
}
```

把它粘贴到客户端的 MCP 配置中，例如 Claude Desktop 的
`~/Library/Application Support/Claude/claude_desktop_config.json`，然后重启客户端。

源码开发环境下也可以直接用模块入口（`--print-config` 在找不到 `nexa` 可执行文件时会给出这种形式）：

```bash
python -m app.mcp
```

## 工具清单

### 只读（默认注册）

| 工具 | 说明 |
| --- | --- |
| `list_targets` | 列出所有 target（id、root domain、program） |
| `get_target` | 按数字 id 或域名取单个 target |
| `target_summary` | 资产/服务/存活数量、组件、降噪统计与来源覆盖 |
| `search_assets` | 目标内查询 DSL 搜索服务 |
| `list_services` | 分页列出已探测的 HTTP 服务 |
| `list_assets` | 分页列出主机资产（存活状态、来源） |
| `list_apps` | 聚合组件/技术指纹 |
| `list_interesting` | 优先关注资产（discovery ≥ 45 且 noise < 80） |
| `list_noise` | 降噪/清理候选（noise ≥ 60） |
| `list_outliers` | 大型模板组中的疑似高价值异常 |
| `list_groups` | 重复服务模板组 |
| `get_group_assets` | 某个模板组内的资产明细 |
| `inspect_service` | 分类原因 + 响应头 + 来源证据（即 CLI 的 `why`） |
| `list_evidence` | 来源证据行（哪个来源/provider 发现了什么） |
| `source_coverage` | 各来源的证据计数 |
| `online_search` | 调用已启用的 FOFA / Hunter / Shodan / ZoomEye / 360 Quake |
| `cve_poc` | 查询某个 CVE 的公开 GitHub PoC 元数据 |

每个工具都对 `limit` 做了上限钳制（普通视图 200，资产列表 200），避免把整库拉进模型上下文。

### 可选（需要显式开启）

| 工具 | 说明 |
| --- | --- |
| `scan_target` | 触发完整梳理流水线（subfinder / OneForAll / CT / Wayback / httpx）并重新降噪 |

默认**不注册** `scan_target`，因为它会运行外部工具、耗时可能达数分钟。需要时：

```bash
nexa mcp --allow-scan
```

对应的配置片段用 `nexa mcp --print-config --allow-scan` 生成。

## 查询语法

`search_assets` 使用与 CLI/Web 完全一致的语法，字段别名见 `app/query.py`：

```text
app="Vue.js" && server="nginx"
status=200 && title="admin"
cdn!="cloudflare"
host="api" || host="admin"
category="admin"
```

操作符：`=`、`!=`；布尔逻辑：`&&`、`||`。

## 故障排查

- **客户端读不到工具**：确认 `nexa mcp` 能在终端直接启动，并且没有把其它输出写进 stdout；stdout 只允许 JSON-RPC，人类可读信息一律走 stderr。
- **返回数据为空**：数据库里还没有该目标的数据，先在 CLI/Web 里跑一次扫描。
- **`online_search` 报 provider disabled**：在 `nexa web` 的 Providers 面板或 `config/nexa.toml` 中启用对应 provider 并填写 key。
- **调用超时**：`scan_target` 会运行外部工具，请调大客户端超时；只读工具不会超时。

## 安全边界

- 仅本地 stdio，不开放网络端口。
- 只读工具不会修改扫描得到的资产/服务数据（首次查询某个目标时可能补算派生的降噪分类缓存）；`scan_target` 只做资产收集与指纹探测，不做漏洞利用。
- 所有工具都限定在已授权的 in-scope 目标数据范围内。
