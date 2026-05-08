import re
from dataclasses import dataclass
from typing import Any

from sqlmodel import Session, select

from app.models.asset import Asset
from app.models.service import Service


class QuerySyntaxError(ValueError):
    """Raised when a target search query cannot be parsed."""


@dataclass(frozen=True)
class SearchRow:
    asset: Asset
    service: Service | None


@dataclass(frozen=True)
class QueryTerm:
    field: str
    operator: str
    value: str


FIELD_ALIASES = {
    "app": "technologies",
    "apps": "technologies",
    "tech": "technologies",
    "technology": "technologies",
    "technologies": "technologies",
    "ip": "ip",
    "host": "host",
    "domain": "host",
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
    "alive": "is_alive",
}

TERM_RE = re.compile(
    r"^\s*(?P<field>[a-zA-Z_][a-zA-Z0-9_-]*)\s*(?P<op>!=|=)\s*"
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
        select(Asset, Service)
        .join(Service, Service.asset_id == Asset.id, isouter=True)
        .where(Asset.target_id == target_id)
        .order_by(Asset.host, Service.url)
    )
    return [SearchRow(asset=asset, service=service) for asset, service in session.exec(statement).all()]


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
