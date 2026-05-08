from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class APIEndpoint(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    source: str = Field(index=True)
    method: str | None = Field(default=None, index=True)
    path: str = Field(index=True)
    full_url: str | None = Field(default=None, index=True)
    api_type: str | None = Field(default=None, index=True)
    auth_required_guess: bool | None = Field(default=None, index=True)
    risk_tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))

