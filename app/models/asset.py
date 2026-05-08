from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class Asset(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    host: str = Field(index=True, unique=True)
    asset_type: str = Field(default="subdomain", index=True)
    source: str = Field(default="manual", index=True)
    ip: str | None = Field(default=None, index=True)
    cname: str | None = None
    is_alive: bool = Field(default=False, index=True)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)

