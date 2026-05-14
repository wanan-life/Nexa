import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True)
class ScanToolDefaults:
    subfinder: bool = True
    oneforall: bool = True
    httpx: bool = True
    online_providers: bool = True
    online_limit: int = 30


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    email: str = ""
    fields: str = ""
    page_size: int = 100
    is_web: int | None = None
    status_code: str = ""
    start_time: str = ""
    end_time: str = ""


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="NEXA_", env_file=".env", extra="ignore")

    project_root: Path = Field(default_factory=lambda: Path(__file__).resolve().parents[1])
    data_dir: Path | None = None
    database_url: str | None = None
    log_level: str = "INFO"

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir or self.project_root / "data"

    @property
    def tools_dir(self) -> Path:
        return self.project_root / "tools"

    @property
    def config_dir(self) -> Path:
        return self.project_root / "config"

    @property
    def scan_manifest_path(self) -> Path:
        return self.config_dir / "scan.toml"

    @property
    def provider_manifest_path(self) -> Path:
        return self.config_dir / "providers.toml"

    @property
    def app_config_path(self) -> Path:
        return self.config_dir / "nexa.toml"

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.resolved_data_dir / "nexa.db"
        return f"sqlite:///{db_path}"

    @property
    def scan_tool_defaults(self) -> ScanToolDefaults:
        data = self._config_data()
        if data:
            scan = data.get("scan", {})
            tools = scan.get("tools", {}) if isinstance(scan, dict) else {}
            online = scan.get("online", {}) if isinstance(scan, dict) else {}
            return ScanToolDefaults(
                subfinder=_as_bool(tools.get("subfinder"), default=True),
                oneforall=_as_bool(tools.get("oneforall"), default=True),
                httpx=_as_bool(tools.get("httpx"), default=True),
                online_providers=_as_bool(online.get("providers"), default=True),
                online_limit=_as_int(online.get("limit"), default=30),
            )

        if not self.scan_manifest_path.exists():
            return ScanToolDefaults()

        data = tomllib.loads(self.scan_manifest_path.read_text(encoding="utf-8"))
        tools = data.get("tools", {})
        return ScanToolDefaults(
            subfinder=_as_bool(tools.get("subfinder"), default=True),
            oneforall=_as_bool(tools.get("oneforall"), default=True),
            httpx=_as_bool(tools.get("httpx"), default=True),
            online_providers=True,
        )

    @property
    def provider_configs(self) -> dict[str, ProviderConfig]:
        data = self._config_data()
        if not data:
            if not self.provider_manifest_path.exists():
                return {}
            data = tomllib.loads(self.provider_manifest_path.read_text(encoding="utf-8"))
        providers = data.get("providers", {})
        configs: dict[str, ProviderConfig] = {}
        for name, raw in providers.items():
            if not isinstance(raw, dict):
                continue
            configs[name] = ProviderConfig(
                name=name,
                enabled=_as_bool(raw.get("enabled"), default=False),
                base_url=str(raw.get("base_url") or ""),
                api_key=str(raw.get("api_key") or raw.get("key") or ""),
                email=str(raw.get("email") or ""),
                fields=str(raw.get("fields") or ""),
                page_size=_as_int(raw.get("page_size"), default=100),
                is_web=_as_optional_int(raw.get("is_web")),
                status_code=str(raw.get("status_code") or ""),
                start_time=str(raw.get("start_time") or ""),
                end_time=str(raw.get("end_time") or ""),
            )
        return configs

    def _config_data(self) -> dict:
        if not self.app_config_path.exists():
            return {}
        return tomllib.loads(self.app_config_path.read_text(encoding="utf-8"))

    def ensure_app_config(self) -> Path:
        if self.app_config_path.exists():
            return self.app_config_path

        self.config_dir.mkdir(parents=True, exist_ok=True)
        legacy_scan = {}
        legacy_providers = {}
        if self.scan_manifest_path.exists():
            legacy_scan = tomllib.loads(self.scan_manifest_path.read_text(encoding="utf-8"))
        if self.provider_manifest_path.exists():
            legacy_providers = tomllib.loads(self.provider_manifest_path.read_text(encoding="utf-8"))

        if legacy_scan or legacy_providers:
            self.app_config_path.write_text(
                _render_app_config(legacy_scan, legacy_providers),
                encoding="utf-8",
            )
            return self.app_config_path

        example = self.config_dir / "nexa.example.toml"
        if example.exists():
            self.app_config_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            return self.app_config_path

        self.app_config_path.write_text(_render_app_config({}, {}), encoding="utf-8")
        return self.app_config_path


def _as_bool(value: object, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_int(value: object, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_optional_int(value: object) -> int | None:
    if value is None or value == "":
        return None


def _render_app_config(scan_data: dict, provider_data: dict) -> str:
    tools = scan_data.get("tools", {}) if isinstance(scan_data.get("tools", {}), dict) else {}
    providers = provider_data.get("providers", {})
    if not isinstance(providers, dict):
        providers = {}

    lines = [
        "[scan.tools]",
        f"subfinder = {_toml_bool(_as_bool(tools.get('subfinder'), default=True))}",
        f"oneforall = {_toml_bool(_as_bool(tools.get('oneforall'), default=True))}",
        f"httpx = {_toml_bool(_as_bool(tools.get('httpx'), default=True))}",
        "",
        "[scan.online]",
        "providers = true",
        "limit = 30",
        "",
    ]
    if providers:
        for name, raw in providers.items():
            if not isinstance(raw, dict):
                continue
            lines.extend(_render_provider_section(str(name), raw))
    else:
        for name in ("fofa", "hunter_qianxin", "shodan", "zoomeye"):
            lines.extend(_render_provider_section(name, {}))
    return "\n".join(lines).rstrip() + "\n"


def _render_provider_section(name: str, raw: dict) -> list[str]:
    defaults = {
        "fofa": {
            "base_url": "https://fofa.info/api/v1/search/all",
            "fields": "host,ip,port,protocol,title,server,domain",
            "page_size": 100,
        },
        "hunter_qianxin": {
            "base_url": "https://hunter.qianxin.com/openApi/search",
            "page_size": 10,
            "is_web": 1,
            "status_code": "",
            "start_time": "",
            "end_time": "",
        },
        "shodan": {
            "base_url": "https://api.shodan.io/shodan/host/search",
            "page_size": 100,
        },
        "zoomeye": {
            "base_url": "https://api.zoomeye.org/data/search",
            "page_size": 100,
        },
    }
    merged = defaults.get(name, {}) | raw
    if "api_key" not in merged and "key" in merged:
        merged["api_key"] = merged["key"]
    keys = [
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
    ]
    lines = [f"[providers.{name}]"]
    for key in keys:
        if key not in merged:
            continue
        value = merged[key]
        if key == "enabled":
            lines.append(f"enabled = {_toml_bool(_as_bool(value, default=False))}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f'{key} = "{_escape_toml_string(str(value or ""))}"')
    lines.append("")
    return lines


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _escape_toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
