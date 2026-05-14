from __future__ import annotations

from app.config import ProviderConfig
from app.providers.base import OnlineAssetResult, OnlineSearchMeta, ProviderDisabledError
from app.providers.clients import build_provider
from app.providers.query import translate_provider_query


def search_online_assets(
    query: str,
    configs: dict[str, ProviderConfig],
    provider_name: str = "all",
    limit: int = 50,
) -> tuple[list[OnlineAssetResult], list[str], list[OnlineSearchMeta]]:
    selected = _select_configs(configs, provider_name)
    results: list[OnlineAssetResult] = []
    errors: list[str] = []
    metas: list[OnlineSearchMeta] = []

    for config in selected:
        try:
            provider = build_provider(config)
            provider_query = translate_provider_query(query, config.name)
            provider_results, meta = provider.search(provider_query, limit=max(1, limit - len(results)))
            results.extend(provider_results)
            metas.append(meta)
        except ProviderDisabledError as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"{config.name}: {exc}")
        if len(results) >= limit:
            break

    return results[:limit], errors, metas


def _select_configs(configs: dict[str, ProviderConfig], provider_name: str) -> list[ProviderConfig]:
    if provider_name == "all":
        return [config for config in configs.values() if config.enabled]
    config = configs.get(provider_name)
    if not config:
        raise ValueError(f"unknown provider: {provider_name}")
    return [config]
