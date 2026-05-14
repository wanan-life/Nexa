# Nexa

[中文文档](README.md) | English

![nexa](docs/images/nexa.svg)

Nexa is a lightweight early-stage reconnaissance workspace for authorized bug bounty, SRC, and internal security testing.

The name comes from “Nexus” and “Next”: Nexa is intended to be a small connection hub for targets, assets, HTTP fingerprints, cyberspace search providers, and target-scoped local queries.

Nexa intentionally stays focused on pre-engagement asset mapping:

```text
Collect assets -> Normalize -> Probe HTTP -> Store fingerprints -> Search by target -> Export for review
```

It does not include destructive exploitation, automated vulnerability exploitation, authentication bypass, deep application fuzzing, JavaScript API extraction, or Burp-like request testing.

## Install

Requirements:

- Python 3.11+
- Bundled tool bootstrap detects the current OS/CPU architecture

```bash
git clone <your-repo-url> nexa
cd nexa
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nexa init
```

Download missing bundled tools:

```bash
nexa init --bootstrap-tools
```

Check bundled tool status:

```bash
nexa tools
```

Copy the local configuration template:

```bash
cp config/nexa.example.toml config/nexa.toml
```

## Quick Start

Create and list targets:

```bash
nexa add-target jd.com --program-name "JD SRC" --scope-type in-scope
nexa targets
```

Run target-level collection:

```bash
nexa target 1 --scan
```

Refresh HTTP probing for existing assets:

```bash
nexa scan-http --target jd.com
```

Enter target-scoped search:

```bash
nexa use 1
```

Example local queries:

```text
app="Vue.js"
ip="127.0.0.1"
server="nginx" && status=200
cdn!="cloudflare"
alive=true
```

One-shot query:

```bash
nexa use 1 -q 'server="nginx" && status=200'
```

Online provider query, after enabling API keys in `config/nexa.toml`:

```bash
nexa online-search 'domain.suffix="example.com"' --provider fofa --limit 30
```

Delete a target:

```bash
nexa delete-target jd.com
nexa del-target jd.com
```

## Authorship

- Primary author and developer: OpenAI Codex
- Original idea and product direction: wanan

This note documents how the repository was generated and developed: the user provided the initial idea and requirements for a bug bounty asset reconnaissance system, while OpenAI Codex handled the architecture, implementation, documentation, and iterative development.
