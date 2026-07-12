from __future__ import annotations

from dataclasses import dataclass

from app.collectors.base import CollectedAsset
from app.models.asset import Asset
from app.models.evidence import AssetSeed
from app.utils.normalize import normalize_host


HIGH_VALUE_PREFIXES = (
    "account",
    "admin",
    "api",
    "app",
    "auth",
    "b",
    "backend",
    "console",
    "dev",
    "gateway",
    "login",
    "m",
    "manage",
    "manager",
    "merchant",
    "open",
    "order",
    "partner",
    "passport",
    "pay",
    "portal",
    "pre",
    "seller",
    "sso",
    "supplier",
    "test",
    "uat",
    "user",
    "vpn",
)

ENV_SUFFIXES = ("dev", "test", "pre", "uat", "staging")


@dataclass(frozen=True)
class ExpansionResult:
    name: str
    assets: list[CollectedAsset]


def expand_from_patterns(root_domain: str, known_assets: list[Asset], limit: int = 250) -> ExpansionResult:
    root = normalize_host(root_domain)
    candidates: list[str] = []
    existing = {asset.host for asset in known_assets}

    for prefix in HIGH_VALUE_PREFIXES:
        _append_candidate(candidates, existing, f"{prefix}.{root}", limit)
        if len(candidates) >= limit:
            break

    labels = [_leftmost_label(asset.host, root) for asset in known_assets]
    for label in labels:
        if len(candidates) >= limit:
            break
        if not label or label in HIGH_VALUE_PREFIXES:
            continue
        for marker in ("api", "admin", "m", "open", "pay"):
            _append_candidate(candidates, existing, f"{marker}-{label}.{root}", limit)
            _append_candidate(candidates, existing, f"{label}-{marker}.{root}", limit)
            if len(candidates) >= limit:
                break

    return ExpansionResult(
        name="pattern_expansion",
        assets=[CollectedAsset(host=host, source="pattern_expansion") for host in candidates],
    )


def expand_from_seeds(root_domain: str, seeds: list[AssetSeed], limit: int = 250) -> ExpansionResult:
    root = normalize_host(root_domain)
    candidates: list[str] = []
    existing = {seed.host for seed in seeds}

    for seed in seeds:
        if len(candidates) >= limit:
            break
        label = _leftmost_label(seed.host, root)
        if not label:
            continue
        for suffix in ENV_SUFFIXES:
            _append_candidate(candidates, existing, f"{label}-{suffix}.{root}", limit)
            _append_candidate(candidates, existing, f"{suffix}-{label}.{root}", limit)
        for prefix in ("api", "admin", "open", "m", "gateway"):
            _append_candidate(candidates, existing, f"{prefix}-{label}.{root}", limit)
            _append_candidate(candidates, existing, f"{label}-{prefix}.{root}", limit)

    return ExpansionResult(
        name="seed_expansion",
        assets=[CollectedAsset(host=host, source="seed_expansion") for host in candidates],
    )


def _append_candidate(candidates: list[str], existing: set[str], host: str, limit: int) -> None:
    normalized = normalize_host(host)
    if len(candidates) >= limit or not normalized or normalized in existing or normalized in candidates:
        return
    candidates.append(normalized)


def _leftmost_label(host: str, root_domain: str) -> str:
    normalized = normalize_host(host)
    suffix = f".{root_domain}"
    if not normalized.endswith(suffix):
        return ""
    relative = normalized[: -len(suffix)]
    return relative.split(".")[0] if relative else ""
