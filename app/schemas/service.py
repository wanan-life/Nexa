from datetime import datetime
from typing import Any

from sqlmodel import SQLModel


class ServiceCreate(SQLModel):
    asset_id: int
    url: str
    scheme: str | None = None
    port: int | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    favicon_hash: str | None = None
    server: str | None = None
    cdn: str | None = None
    waf: str | None = None
    technologies: list[str] = []
    response_headers: dict[str, Any] = {}
    screenshot_path: str | None = None


class ServiceRead(SQLModel):
    id: int
    asset_id: int
    url: str
    scheme: str
    port: int | None
    status_code: int | None
    title: str | None
    content_length: int | None
    favicon_hash: str | None
    server: str | None
    cdn: str | None
    waf: str | None
    technologies: list[str]
    response_headers: dict[str, Any]
    screenshot_path: str | None
    last_checked_at: datetime | None

