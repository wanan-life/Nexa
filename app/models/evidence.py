from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class AssetEvidence(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    asset_id: int | None = Field(default=None, foreign_key="asset.id", index=True)
    service_id: int | None = Field(default=None, foreign_key="service.id", index=True)
    source: str = Field(index=True)
    provider: str | None = Field(default=None, index=True)
    query: str | None = None
    query_type: str | None = Field(default=None, index=True)
    raw_host: str | None = Field(default=None, index=True)
    raw_url: str | None = Field(default=None, index=True)
    ip: str | None = Field(default=None, index=True)
    port: int | None = Field(default=None, index=True)
    title: str | None = None
    confidence: int = Field(default=50, index=True)
    raw_snapshot: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)


class AssetSeed(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    host: str = Field(index=True)
    source: str = Field(default="manual", index=True)
    note: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
