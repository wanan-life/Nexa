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
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.resolved_data_dir / "nexa.db"
        return f"sqlite:///{db_path}"

    @property
    def scan_tool_defaults(self) -> ScanToolDefaults:
        if not self.scan_manifest_path.exists():
            return ScanToolDefaults()

        data = tomllib.loads(self.scan_manifest_path.read_text(encoding="utf-8"))
        tools = data.get("tools", {})
        return ScanToolDefaults(
            subfinder=_as_bool(tools.get("subfinder"), default=True),
            oneforall=_as_bool(tools.get("oneforall"), default=True),
            httpx=_as_bool(tools.get("httpx"), default=True),
        )


def _as_bool(value: object, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()
