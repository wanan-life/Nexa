# Nexa

[中文](README.md) | English

![Nexa](docs/images/nexa.svg)

## Introduction

Nexa is an attack-surface intelligence tool for authorized bug bounty, SRC, and internal security testing. Its name combines “Nexus” and “Next”: Nexa connects asset sources, HTTP services, technology fingerprints, and evidence into searchable, reviewable target views.

```text
Collect -> Normalize -> Probe HTTP -> Store fingerprints -> Reduce noise -> Search by target
```

Nexa provides both a CLI and an integrated Web workspace. It supports subfinder, OneForAll, httpx, CT logs, Wayback, and optional FOFA, Hunter, Shodan, ZoomEye, and 360 Quake queries, plus a built-in MCP server for AI clients. It does not include destructive exploitation or automated vulnerability exploitation.

## Install

Download the single-file executable for your platform from [Releases](https://github.com/wanan-life/Nexa/releases). The current release provides:

- `nexa-v0.3.0-macos-arm64`: Apple Silicon Mac

macOS installation:

```bash
chmod +x nexa-v0.3.0-macos-arm64
xattr -d com.apple.quarantine nexa-v0.3.0-macos-arm64 2>/dev/null || true
sudo mv nexa-v0.3.0-macos-arm64 /usr/local/bin/nexa
nexa init
```

The Nexa executable does not require Python, Node.js, or a source checkout. `nexa init` creates `~/.nexa/` and offers to download platform-specific subfinder, httpx, and OneForAll tools. The OneForAll integration requires a system Python 3 installation.

Runtime data is stored under:

```text
~/.nexa/data/nexa.db
~/.nexa/config/nexa.toml
~/.nexa/config/noise_rules.json
~/.nexa/tools/
```

Source development instructions are available in [Development](docs/development.md).

## Quick Start

```bash
nexa init
nexa add-target example.com --program-name "Example SRC"
nexa target 1 --scan
nexa use 1
nexa web
```

Web: `http://127.0.0.1:8000`

API documentation: `http://127.0.0.1:8000/docs`

Interactive examples:

```text
overview
services
apps
app="Vue.js" && server="nginx"
status=200 && title="admin"
inspect 123
clean
```

The interactive shell completes: **Tab** opens candidates for commands and query fields (a bare `app` ⇥ → `app=`, `status=` ⇥ → 200/301/404..., `clean st` ⇥ → `clean status=`), and **→** accepts the dim inline hint (typing `ov` suggests `erview`). `↑` searches history by prefix.

## Scanning and speed

`nexa target <ref> --scan` skips hosts that were already probed and found dead, re-probing only live assets plus anything discovered since the last probe (jd.com drops from 31,051 candidates to ~3,068). Force a full re-probe with:

```bash
nexa target 1 --scan --rescan-dead
```

Scans stream batch progress and a heartbeat (`httpx batch 3/8: 512 responses, 1200 lines, 40s elapsed`), and each batch is persisted as soon as it finishes, so a timeout or interrupt never discards completed work. Tune concurrency and timeouts under `[scan.tools]` in `config/nexa.toml`: `httpx_threads`, `httpx_rate_limit`, `httpx_request_timeout`, `httpx_retries`, `httpx_batch_size`, `httpx_timeout`.

## AI / MCP integration

Nexa ships an MCP (Model Context Protocol) server that exposes local asset intelligence to MCP-capable AI clients (Claude Desktop, DSH, Cursor, ...) over stdio:

```bash
# Generate a client config snippet
nexa mcp --print-config

# Also allow the AI to trigger a full recon scan
nexa mcp --print-config --allow-scan
```

By default only 17 read-only tools are registered (targets, services, fingerprints, noise reduction, source evidence, online mapping providers, CVE PoC lookup). `scan_target`, which runs external tools, requires `--allow-scan`. See [MCP guide](docs/mcp.md) for setup, the tool list, and query syntax.

## Authorship

- Primary author and developer: OpenAI Codex
- Original idea and product direction: wanan

The user provided the original bug bounty asset-intelligence concept, field feedback, and product direction. OpenAI Codex handled architecture, implementation, documentation, and iterative development.
