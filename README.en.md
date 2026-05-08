# Nexa

[中文文档](README.md) | English

Nexa is a bug bounty attack surface intelligence platform for authorized reconnaissance workflows.

The name Nexa comes from “Nexus” and “Next”: it is intended to be a connection hub for assets, fingerprints, risk rules, search syntax, and AI-assisted analysis, while pointing toward next-generation security intelligence workflows.

It is not intended to be "another scanner" that only concatenates outputs from subdomain and HTTP probing tools. The goal is to turn noisy early-stage recon data into normalized, searchable, explainable, and eventually scoreable intelligence.

```text
Assets -> Normalize -> Fingerprint -> Search -> Score -> Prioritize -> AI-assisted review
```

Nexa currently focuses on the first half of that pipeline: target management, subdomain ingestion, HTTP service probing, fingerprint storage, and target-scoped search.

## Features

- Target-centric asset database
- SQLite storage with SQLModel models
- CLI-first workflow powered by Typer and Rich
- FastAPI skeleton for future API/MCP integration
- Bundled tool resolution from `tools/`
- Integrated adapters for:
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [OneForAll](https://github.com/shmilylty/OneForAll)
- Import existing subdomain and httpx JSONL results
- Run a target-level recon pipeline with one command
- Interactive target workspace with FOFA/ZoomEye-like query syntax
- English and Chinese grouped CLI help
- Data model placeholders for JS files, API endpoints, fingerprints, and risk findings

## Security Boundary

Nexa is only for legal, authorized bug bounty, SRC, internal security testing, and lab environments.

The project does not include destructive exploitation, automated vulnerability exploitation, authentication bypass, or bulk attack logic. The current implementation is limited to asset collection, normalization, HTTP probing, fingerprint storage, and local analysis support.

## Install

Requirements:

- Python 3.11+
- macOS arm64 is currently the tested platform for bundled tool bootstrap

```bash
git clone <your-repo-url> nexa
cd nexa
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nexa init
```

Default database:

```text
data/nexa.db
```

You may override the database/data directory if needed:

```bash
export NEXA_DATABASE_URL="sqlite:////absolute/path/nexa.db"
export NEXA_DATA_DIR="/absolute/path/data"
```

## Bundled Tools

Nexa resolves external recon tools from the project-local `tools/` directory. It does not rely on your system `PATH` for scanning.

Expected structure:

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

Check bundled tool status:

```bash
nexa tools
```

Bootstrap tools:

```bash
python scripts/bootstrap_tools.py
```

The bootstrap script currently installs:

- subfinder `v2.14.0` macOS arm64 release
- httpx `v1.9.0` macOS arm64 release
- OneForAll from GitHub, with a local `.venv`

If a bundled tool is missing or fails, Nexa reports the error in the Nexa summary and continues when possible.

## Quick Start

Create a target:

```bash
nexa add-target jd.com --program-name "JD SRC" --scope-type in-scope
nexa targets
```

Run target-level collection:

```bash
nexa target 1 --scan
```

This runs the configured target pipeline:

1. Collect subdomains with bundled subfinder.
2. Collect subdomains with bundled OneForAll.
3. Deduplicate and normalize assets.
4. Probe HTTP services with bundled httpx.
5. Store alive services and HTTP fingerprints.

You can also run the same pipeline by name:

```bash
nexa collect-target --target jd.com
```

Probe only existing assets:

```bash
nexa scan-http --target jd.com
```

## Import Existing Results

Import subdomain lists:

```bash
nexa import-subdomains --target jd.com --file subdomains.txt --source subfinder
nexa import-subdomains --target jd.com --file oneforall.csv --source oneforall
```

Import ProjectDiscovery httpx JSONL:

```bash
nexa import-httpx --target jd.com --file httpx.jsonl
```

## Target Search

Enter an interactive target workspace:

```bash
nexa use 1
nexa use jd.com
```

Prompt style:

```text
jd.com >
```

The interactive prompt supports cursor movement, command history, and line editing through `prompt_toolkit`.

Example queries:

```text
app="Vue.js"
ip="127.0.0.1"
server="nginx" && status=200
app="vue" || title="admin"
cdn!="cloudflare"
alive=true
```

Run a one-shot query without entering the shell:

```bash
nexa use 1 -q 'app="vue.js" && server="nginx"'
```

Supported fields:

```text
app, tech, ip, host, url, title, server, cdn, waf,
status, port, scheme, source, cname, favicon, alive
```

Supported operators:

```text
=
!=
&&
||
```

## CLI Help

Default help is English:

```bash
nexa --help
```

Grouped English help:

```bash
nexa --help-en
```

Grouped Chinese help:

```bash
nexa --help-zh
```

## API

Run the FastAPI app:

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

The API is intentionally minimal right now. The main workflow is CLI-first, while the API layer is reserved for future dashboard and MCP/AI integrations.

## Data Model

Current core models:

- `Target`: bug bounty/SRC target, root domain, scope metadata
- `Asset`: subdomain or host, source, IP/CNAME, alive state
- `Service`: HTTP/HTTPS service, status, title, server, CDN/WAF, technologies, headers
- `JSFile`: frontend JavaScript file metadata
- `APIEndpoint`: API endpoint extracted from JS, Swagger, HTML, logs, etc.
- `Fingerprint`: structured service fingerprint
- `RiskFinding`: future risk finding and scoring output

## Project Structure

```text
app/
  main.py              FastAPI entrypoint
  config.py            Settings
  database.py          SQLite/SQLModel setup
  repositories.py      Data access layer
  query.py             Target search syntax
  tooling.py           Bundled tool resolver
  models/              SQLModel database models
  schemas/             Input/output schemas
  collectors/          External tool adapters and parsers
  pipelines/           Target-level recon orchestration
  analyzers/           HTTP/JS/tech/risk analyzer placeholders
  scoring/             Rule scoring placeholders
  cli/                 Typer CLI
  utils/               Normalization and logging helpers
scripts/
  bootstrap_tools.py   Bundled tool installer
tools/
  README.md            Bundled tool layout
data/
  nexa.db            Default SQLite database
```

## Roadmap

- Improve httpx field compatibility and response header normalization
- Add favicon mmh3 hashing support
- Add JS collection and sourcemap detection
- Extract API endpoints from JS, HTML, Swagger/OpenAPI, and common docs paths
- Implement rule-based risk scoring
- Implement `nexa top --target ...`
- Implement Markdown export for high-value assets
- Add MCP tools:
  - `search_assets`
  - `get_service_detail`
  - `get_js_endpoints`
  - `get_risk_findings`
  - `summarize_target`

The long-term design is that AI agents should read compressed, filtered, target-scoped intelligence instead of raw bulk recon output.

## Authorship

- Primary author and developer: OpenAI Codex
- Original idea and product direction: wanan

This note documents how the repository was generated and developed: the user provided the initial idea and requirements for a bug bounty asset intelligence system, while OpenAI Codex handled the architecture, implementation, documentation, and iterative development.

## Legal Notice

Use this project only against assets you own or are explicitly authorized to test. You are responsible for complying with all laws, bug bounty rules, rate limits, and scope restrictions.
