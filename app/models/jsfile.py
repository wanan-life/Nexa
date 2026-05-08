from sqlmodel import Field, SQLModel


class JSFile(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    url: str = Field(index=True, unique=True)
    content_hash: str | None = Field(default=None, index=True)
    size: int | None = None
    is_sourcemap_found: bool = Field(default=False, index=True)
    discovered_api_count: int = 0
    discovered_secret_count: int = 0

