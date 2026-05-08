from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.common import utc_now


class Target(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    root_domain: str = Field(index=True)
    program_name: str | None = None
    scope_type: str = Field(default="in-scope", index=True)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

