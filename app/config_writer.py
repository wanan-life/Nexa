from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "fofa": {
        "enabled": False,
        "email": "",
        "api_key": "",
        "base_url": "https://fofa.info/api/v1/search/all",
        "fields": "host,ip,port,protocol,title,server,domain",
        "page_size": 100,
    },
    "hunter_qianxin": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://hunter.qianxin.com/openApi/search",
        "page_size": 10,
        "is_web": 1,
        "status_code": "",
        "start_time": "",
        "end_time": "",
    },
    "shodan": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://api.shodan.io/shodan/host/search",
        "page_size": 100,
    },
    "zoomeye": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://api.zoomeye.org/data/search",
        "page_size": 100,
    },
    "quake_360": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://quake.360.net/api/v3/search/quake_service",
        "page_size": 100,
    },
}


def read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def update_provider_config(path: Path, provider: str, updates: dict[str, Any]) -> dict[str, Any]:
    data = read_toml(path)
    providers = data.setdefault("providers", {})
    current = providers.setdefault(provider, {})
    if not isinstance(current, dict):
        current = {}
        providers[provider] = current
    allowed = {
        "enabled",
        "email",
        "api_key",
        "base_url",
        "fields",
        "page_size",
        "is_web",
        "status_code",
        "start_time",
        "end_time",
    }
    for key, value in updates.items():
        if key in allowed and value is not None:
            current[key] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_app_config(data), encoding="utf-8")
    return read_toml(path)


def render_app_config(data: dict[str, Any]) -> str:
    scan = data.get("scan", {}) if isinstance(data.get("scan"), dict) else {}
    tools = scan.get("tools", {}) if isinstance(scan.get("tools"), dict) else {}
    online = scan.get("online", {}) if isinstance(scan.get("online"), dict) else {}
    intel = data.get("intel", {}) if isinstance(data.get("intel"), dict) else {}
    cve = intel.get("cve_exploit", {}) if isinstance(intel.get("cve_exploit"), dict) else {}
    providers = data.get("providers", {}) if isinstance(data.get("providers"), dict) else {}

    lines = [
        "[scan.tools]",
        f"subfinder = {_bool(tools.get('subfinder', True))}",
        f"oneforall = {_bool(tools.get('oneforall', True))}",
        f"httpx = {_bool(tools.get('httpx', True))}",
        f"ct_logs = {_bool(tools.get('ct_logs', True))}",
        f"wayback = {_bool(tools.get('wayback', True))}",
        f"seed_expansion = {_bool(tools.get('seed_expansion', True))}",
        f"pattern_expansion = {_bool(tools.get('pattern_expansion', True))}",
        f"ct_limit = {_int(tools.get('ct_limit'), 500)}",
        f"wayback_limit = {_int(tools.get('wayback_limit'), 300)}",
        f"expansion_limit = {_int(tools.get('expansion_limit'), 250)}",
        f"extracted_probe_limit = {_int(tools.get('extracted_probe_limit'), 300)}",
        f"httpx_batch_size = {_int(tools.get('httpx_batch_size'), 2000)}",
        f"httpx_timeout = {_int(tools.get('httpx_timeout'), 900)}",
        f"httpx_enrich_limit = {_int(tools.get('httpx_enrich_limit'), 1000)}",
        "",
        "[scan.online]",
        f"providers = {_bool(online.get('providers', False))}",
        f"limit = {_int(online.get('limit'), 30)}",
        "",
        "[intel.cve_exploit]",
        f"enabled = {_bool(cve.get('enabled', True))}",
        f'base_url = "{_escape(str(cve.get("base_url") or "https://poc-in-github.motikan2010.net/api/v1/"))}"',
        f"timeout = {_int(cve.get('timeout'), 15)}",
        "",
    ]
    names = [*PROVIDER_DEFAULTS]
    for provider in providers:
        if provider not in names:
            names.append(provider)
    for name in names:
        merged = PROVIDER_DEFAULTS.get(name, {}) | (
            providers.get(name, {}) if isinstance(providers.get(name), dict) else {}
        )
        lines.extend(_render_provider(name, merged))
    return "\n".join(lines).rstrip() + "\n"


def _render_provider(name: str, values: dict[str, Any]) -> list[str]:
    lines = [f"[providers.{name}]"]
    for key in (
        "enabled",
        "email",
        "api_key",
        "base_url",
        "fields",
        "page_size",
        "is_web",
        "status_code",
        "start_time",
        "end_time",
    ):
        if key not in values:
            continue
        value = values[key]
        if isinstance(value, bool) or key == "enabled":
            lines.append(f"{key} = {_bool(value)}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f'{key} = "{_escape(str(value or ""))}"')
    lines.append("")
    return lines


def _bool(value: Any) -> str:
    if isinstance(value, str):
        return "true" if value.lower() in {"1", "true", "yes", "on"} else "false"
    return "true" if bool(value) else "false"


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
