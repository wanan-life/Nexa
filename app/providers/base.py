from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.config import ProviderConfig


@dataclass(frozen=True)
class OnlineAssetResult:
    provider: str
    host: str = ""
    ip: str = ""
    port: int | None = None
    url: str = ""
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OnlineSearchMeta:
    provider: str
    total: int | None = None
    returned: int = 0
    message: str = ""


class ProviderClient(Protocol):
    name: str

    def search(self, query: str, limit: int) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        raise NotImplementedError


class ProviderDisabledError(RuntimeError):
    pass


class ProviderApiError(RuntimeError):
    pass


def ensure_provider_ready(config: ProviderConfig) -> None:
    if not config.enabled:
        raise ProviderDisabledError(f"provider disabled: {config.name}")
    if config.name in {"fofa"} and (not config.email or not config.api_key):
        raise ProviderDisabledError(f"provider missing email/api_key: {config.name}")
    if config.name != "fofa" and not config.api_key:
        raise ProviderDisabledError(f"provider missing api_key: {config.name}")
