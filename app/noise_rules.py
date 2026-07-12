from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.config import get_settings
from app.models.asset import Asset
from app.models.service import Service


@dataclass(frozen=True)
class NoiseCategoryRule:
    name: str
    category: str
    title_regex: list[str] = field(default_factory=list)
    host_regex: list[str] = field(default_factory=list)
    url_regex: list[str] = field(default_factory=list)
    header_regex: list[str] = field(default_factory=list)
    text_contains: list[str] = field(default_factory=list)
    noise_delta: int = 0
    value_delta: int = 0
    reason: str = ""


@dataclass(frozen=True)
class NoiseRuleSet:
    high_value_keywords: set[str]
    doc_keywords: set[str]
    generic_titles: set[str]
    category_rules: list[NoiseCategoryRule]


@dataclass(frozen=True)
class MatchedNoiseRule:
    rule: NoiseCategoryRule
    reason: str


def load_noise_rules() -> NoiseRuleSet:
    path = _noise_rules_path()
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
    else:
        raw = _default_rules()
    return parse_noise_rules(raw)


def parse_noise_rules(raw: dict) -> NoiseRuleSet:
    rules = NoiseRuleSet(
        high_value_keywords={str(item).lower() for item in raw.get("high_value_keywords", [])},
        doc_keywords={str(item).lower() for item in raw.get("doc_keywords", [])},
        generic_titles={str(item).lower() for item in raw.get("generic_titles", [])},
        category_rules=[
            NoiseCategoryRule(
                name=str(item.get("name") or ""),
                category=str(item.get("category") or "normal"),
                title_regex=[str(value) for value in item.get("title_regex", [])],
                host_regex=[str(value) for value in item.get("host_regex", [])],
                url_regex=[str(value) for value in item.get("url_regex", [])],
                header_regex=[str(value) for value in item.get("header_regex", [])],
                text_contains=[str(value).lower() for value in item.get("text_contains", [])],
                noise_delta=int(item.get("noise_delta") or 0),
                value_delta=int(item.get("value_delta") or 0),
                reason=str(item.get("reason") or item.get("name") or "noise rule"),
            )
            for item in raw.get("category_rules", [])
            if isinstance(item, dict)
        ],
    )
    _validate_rules(rules)
    return rules


def match_category_rules(asset: Asset, service: Service, rules: NoiseRuleSet) -> list[MatchedNoiseRule]:
    matches: list[MatchedNoiseRule] = []
    for rule in rules.category_rules:
        if _matches_rule(asset, service, rule):
            matches.append(MatchedNoiseRule(rule=rule, reason=rule.reason))
    return matches


def _matches_rule(asset: Asset, service: Service, rule: NoiseCategoryRule) -> bool:
    title = service.title or ""
    host = asset.host
    url = service.url
    headers = " ".join(f"{key}: {value}" for key, value in service.response_headers.items())
    text = " ".join([host, url, title, service.server or "", headers]).lower()
    return (
        _any_regex(rule.title_regex, title)
        or _any_regex(rule.host_regex, host)
        or _any_regex(rule.url_regex, url)
        or _any_regex(rule.header_regex, headers)
        or any(value in text for value in rule.text_contains)
    )


def _any_regex(patterns: list[str], value: str) -> bool:
    return any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns)


def _validate_rules(rules: NoiseRuleSet) -> None:
    for rule in rules.category_rules:
        for pattern in [*rule.title_regex, *rule.host_regex, *rule.url_regex, *rule.header_regex]:
            re.compile(pattern)


def _noise_rules_path() -> Path:
    settings = get_settings()
    custom_path = settings.config_dir / "noise_rules.json"
    if custom_path.exists():
        return custom_path
    return settings.config_dir / "noise_rules.example.json"


def _default_rules() -> dict:
    return {
        "high_value_keywords": [
            "admin",
            "api",
            "auth",
            "cas",
            "console",
            "dev",
            "gateway",
            "login",
            "manager",
            "merchant",
            "open",
            "order",
            "partner",
            "pay",
            "portal",
            "pre",
            "sso",
            "supplier",
            "test",
            "uat",
            "user",
        ],
        "doc_keywords": ["swagger", "openapi", "api-docs", "knife4j", "redoc", "graphql"],
        "generic_titles": [
            "",
            "301 moved permanently",
            "302 found",
            "403 forbidden",
            "404 not found",
            "500 internal server error",
            "502 bad gateway",
            "503 service temporarily unavailable",
        ],
        "category_rules": [],
    }
