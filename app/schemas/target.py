from datetime import datetime

from sqlmodel import SQLModel


class TargetCreate(SQLModel):
    name: str
    root_domain: str | None = None
    program_name: str | None = None
    scope_type: str = "in-scope"


class TargetRead(SQLModel):
    id: int
    name: str
    root_domain: str
    program_name: str | None
    scope_type: str
    created_at: datetime
    updated_at: datetime

