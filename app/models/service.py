from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class Service(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    asset_id: int = Field(foreign_key="asset.id", index=True)
    url: str = Field(index=True, unique=True)
    scheme: str = Field(index=True)
    port: int | None = Field(default=None, index=True)
    status_code: int | None = Field(default=None, index=True)
    title: str | None = None
    content_length: int | None = None
    favicon_hash: str | None = Field(default=None, index=True)
    server: str | None = Field(default=None, index=True)
    cdn: str | None = Field(default=None, index=True)
    waf: str | None = Field(default=None, index=True)
    technologies: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    response_headers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    screenshot_path: str | None = None
    last_checked_at: datetime | None = Field(default_factory=utc_now)

