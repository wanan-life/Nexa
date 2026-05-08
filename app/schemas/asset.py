from datetime import datetime

from sqlmodel import SQLModel


class AssetCreate(SQLModel):
    target_id: int
    host: str
    asset_type: str = "subdomain"
    source: str = "manual"
    ip: str | None = None
    cname: str | None = None
    is_alive: bool = False


class AssetRead(SQLModel):
    id: int
    target_id: int
    host: str
    asset_type: str
    source: str
    ip: str | None
    cname: str | None
    is_alive: bool
    first_seen: datetime
    last_seen: datetime

