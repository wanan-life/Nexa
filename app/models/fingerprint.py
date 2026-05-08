from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class Fingerprint(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    name: str = Field(index=True)
    category: str = Field(index=True)
    confidence: float = Field(default=0.0)
    evidence: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

