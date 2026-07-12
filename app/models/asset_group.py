from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class AssetGroup(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    group_type: str = Field(default="template", index=True)
    signature: str = Field(index=True)
    title: str | None = None
    favicon_hash: str | None = Field(default=None, index=True)
    server: str | None = Field(default=None, index=True)
    status_code: int | None = Field(default=None, index=True)
    location: str | None = None
    count: int = Field(default=0, index=True)
    sample_hosts: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    noise_level: str = Field(default="low", index=True)
    reasons: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AssetClassification(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    asset_id: int = Field(foreign_key="asset.id", index=True)
    service_id: int | None = Field(default=None, foreign_key="service.id", index=True)
    group_id: int | None = Field(default=None, foreign_key="assetgroup.id", index=True)
    tier: int = Field(default=3, index=True)
    category: str = Field(default="normal", index=True)
    noise_score: int = Field(default=0, index=True)
    discovery_value: int = Field(default=0, index=True)
    outlier: bool = Field(default=False, index=True)
    reasons: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
