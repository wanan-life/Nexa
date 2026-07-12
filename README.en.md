# Nexa

[中文](README.md) | English

![Nexa](docs/images/nexa.svg)

## Introduction

Nexa is an attack-surface intelligence tool for authorized bug bounty, SRC, and internal security testing. Its name combines “Nexus” and “Next”: Nexa connects asset sources, HTTP services, technology fingerprints, and evidence into searchable, reviewable target views.

```text
Collect -> Normalize -> Probe HTTP -> Store fingerprints -> Reduce noise -> Search by target
```

Nexa provides both a CLI and an integrated Web workspace. It supports subfinder, OneForAll, httpx, CT logs, Wayback, and optional FOFA, Hunter, Shodan, ZoomEye, and 360 Quake queries. It does not include destructive exploitation or automated vulnerability exploitation.

## Install

Download the single-file executable for your platform from [Releases](https://github.com/wanan-life/Nexa/releases). The current release provides:

- `nexa-v0.2.0-macos-arm64`: Apple Silicon Mac

macOS installation:

```bash
chmod +x nexa-v0.2.0-macos-arm64
xattr -d com.apple.quarantine nexa-v0.2.0-macos-arm64 2>/dev/null || true
sudo mv nexa-v0.2.0-macos-arm64 /usr/local/bin/nexa
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

## Authorship

- Primary author and developer: OpenAI Codex
- Original idea and product direction: wanan

The user provided the original bug bounty asset-intelligence concept, field feedback, and product direction. OpenAI Codex handled architecture, implementation, documentation, and iterative development.
