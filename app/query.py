import re
from dataclasses import dataclass
from typing import Any

from sqlmodel import Session, select

from app.models.asset import Asset
from app.models.asset_group import AssetClassification
from app.models.service import Service


class QuerySyntaxError(ValueError):
    """Raised when a target search query cannot be parsed."""


@dataclass(frozen=True)
class SearchRow:
    asset: Asset
    service: Service | None
    classification: AssetClassification | None = None


@dataclass(frozen=True)
class QueryTerm:
    field: str
    operator: str
    value: str


@dataclass(frozen=True)
class AppSummary:
    name: str
    service_count: int
    asset_count: int
    sample_hosts: list[str]


FIELD_ALIASES = {
    "app": "technologies",
    "apps": "technologies",
    "tech": "technologies",
    "technology": "technologies",
    "technologies": "technologies",
    "ip": "ip",
    "host": "host",
    "domain": "host",
    "domain_suffix": "host",
    "domain.suffix": "host",
    "url": "url",
    "title": "title",
    "server": "server",
    "cdn": "cdn",
    "waf": "waf",
    "status": "status_code",
    "status_code": "status_code",
    "code": "status_code",
    "port": "port",
    "scheme": "scheme",
    "source": "source",
    "cname": "cname",
    "favicon": "favicon_hash",
    "favicon_hash": "favicon_hash",
    "header": "response_headers",
    "headers": "response_headers",
    "response_header": "response_headers",
    "response_headers": "response_headers",
    "alive": "is_alive",
    "category": "category",
    "noise": "noise_score",
    "noise_score": "noise_score",
    "value": "discovery_value",
    "discovery_value": "discovery_value",
    "tier": "tier",
    "group": "group_id",
    "group_id": "group_id",
}

TERM_RE = re.compile(
    r"^\s*(?P<field>[a-zA-Z_][a-zA-Z0-9_.-]*)\s*(?P<op>!=|=)\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^&|]+?)\s*$"
)


def search_target_assets(session: Session, target_id: int, query: str, limit: int = 50) -> list[SearchRow]:
    rows = list_target_rows(session, target_id)
    parsed = parse_query(query)
    if not parsed:
        return rows[:limit]
    matched = [row for row in rows if _matches_expression(row, parsed)]
    return matched[:limit]


def list_target_rows(session: Session, target_id: int) -> list[SearchRow]:
    statement = (
        select(Asset, Service, AssetClassification)
        .join(Service, Service.asset_id == Asset.id, isouter=True)
        .join(AssetClassification, AssetClassification.service_id == Service.id, isouter=True)
        .where(Asset.target_id == target_id)
        .order_by(Asset.host, Service.url)
    )
    return [
        SearchRow(asset=asset, service=service, classification=classification)
        for asset, service, classification in session.exec(statement).all()
    ]


def list_target_apps(session: Session, target_id: int, limit: int = 100) -> list[AppSummary]:
    rows = list_target_rows(session, target_id)
    apps: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not row.service or not row.service.technologies:
            continue
        for raw_name in row.service.technologies:
            name = str(raw_name).strip()
            if not name:
                continue
            key = name.lower()
            entry = apps.setdefault(
                key,
                {
                    "name": name,
                    "service_ids": set(),
                    "asset_ids": set(),
                    "hosts": [],
                },
            )
            if row.service.id is not None:
                entry["service_ids"].add(row.service.id)
            if row.asset.id is not None:
                entry["asset_ids"].add(row.asset.id)
            if row.asset.host not in entry["hosts"]:
                entry["hosts"].append(row.asset.host)

    summaries = [
        AppSummary(
            name=str(entry["name"]),
            service_count=len(entry["service_ids"]),
            asset_count=len(entry["asset_ids"]),
            sample_hosts=list(entry["hosts"])[:3],
        )
        for entry in apps.values()
    ]
    return sorted(summaries, key=lambda item: (-item.service_count, item.name.lower()))[:limit]


def parse_query(query: str) -> list[list[QueryTerm]]:
    value = query.strip()
    if not value or value == "*":
        return []

    or_groups = re.split(r"\s+\|\|\s+", value)
    parsed_groups: list[list[QueryTerm]] = []
    for group in or_groups:
        terms = []
        for raw_term in re.split(r"\s+&&\s+", group):
            match = TERM_RE.match(raw_term)
            if not match:
                raise QuerySyntaxError(f"invalid query term: {raw_term}")
            field = match.group("field").lower().replace("-", "_")
            normalized_field = FIELD_ALIASES.get(field)
            if not normalized_field:
                raise QuerySyntaxError(f"unsupported field: {field}")
            terms.append(
                QueryTerm(
                    field=normalized_field,
                    operator=match.group("op"),
                    value=_strip_quotes(match.group("value").strip()),
                )
            )
        parsed_groups.append(terms)
    return parsed_groups


def _matches_expression(row: SearchRow, groups: list[list[QueryTerm]]) -> bool:
    return any(all(_matches_term(row, term) for term in group) for group in groups)


def _matches_term(row: SearchRow, term: QueryTerm) -> bool:
    actual = _field_value(row, term.field)
    matched = _value_matches(actual, term.value)
    return not matched if term.operator == "!=" else matched


def _field_value(row: SearchRow, field: str) -> Any:
    asset_fields = {"host", "ip", "source", "cname", "is_alive"}
    if field in asset_fields:
        return getattr(row.asset, field)
    classification_fields = {"category", "noise_score", "discovery_value", "tier", "group_id"}
    if field in classification_fields:
        return getattr(row.classification, field) if row.classification else None
    if not row.service:
        return None
    return getattr(row.service, field)


def _value_matches(actual: Any, expected: str) -> bool:
    if actual is None:
        return False
    if isinstance(actual, bool):
        return _parse_bool(expected) is actual
    if isinstance(actual, int):
        try:
            return actual == int(expected)
        except ValueError:
            return False
    if isinstance(actual, list):
        expected_lower = expected.lower()
        return any(expected_lower in str(item).lower() for item in actual)
    if isinstance(actual, dict):
        expected_lower = expected.lower()
        return expected_lower in str(actual).lower()
    return expected.lower() in str(actual).lower()


def _parse_bool(value: str) -> bool | None:
    normalized = value.lower()
    if normalized in {"1", "true", "yes", "y", "alive"}:
        return True
    if normalized in {"0", "false", "no", "n", "dead"}:
        return False
    return None


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
