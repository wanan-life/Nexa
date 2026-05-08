from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class RiskFinding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    asset_id: int | None = Field(default=None, foreign_key="asset.id", index=True)
    service_id: int | None = Field(default=None, foreign_key="service.id", index=True)
    finding_type: str = Field(index=True)
    title: str
    description: str
    severity: str = Field(index=True)
    score: int = Field(index=True)
    evidence: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

