from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings


def get_engine():
    settings = get_settings()
    settings.resolved_data_dir.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False}
    return create_engine(settings.resolved_database_url, connect_args=connect_args)


engine = get_engine()


def init_db() -> None:
    from app.models import asset, api_endpoint, fingerprint, jsfile, risk, service, target

    _ = (asset, api_endpoint, fingerprint, jsfile, risk, service, target)
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine, expire_on_commit=False) as session:
        yield session


def create_session() -> Session:
    return Session(engine, expire_on_commit=False)
