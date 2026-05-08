from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.resolved_data_dir / "nexa.db"
        return f"sqlite:///{db_path}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
