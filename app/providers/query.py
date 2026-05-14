from __future__ import annotations

import re

from app.query import QuerySyntaxError, QueryTerm


ONLINE_TERM_RE = re.compile(
    r"^\s*(?P<field>[a-zA-Z_][a-zA-Z0-9_.-]*)\s*(?P<op>!=|=)\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^&|]+?)\s*$"
)


PROVIDER_FIELD_MAPS: dict[str, dict[str, str]] = {
    "fofa": {
        "host": "host",
        "domain_suffix": "domain",
        "ip": "ip",
        "url": "host",
        "title": "title",
        "server": "server",
        "technologies": "app",
        "port": "port",
        "status_code": "status_code",
    },
    "hunter_qianxin": {
        "host": "domain",
        "domain_suffix": "domain.suffix",
        "ip": "ip",
        "url": "url",
        "title": "web.title",
        "server": "component",
        "technologies": "component",
        "port": "port",
        "status_code": "status_code",
    },
    "shodan": {
        "host": "hostname",
        "domain_suffix": "domain",
        "ip": "ip",
        "title": "http.title",
        "server": "product",
        "technologies": "product",
        "port": "port",
    },
    "zoomeye": {
        "host": "site",
        "domain_suffix": "site",
        "ip": "ip",
        "title": "title",
        "server": "app",
        "technologies": "app",
        "port": "port",
    },
}


ONLINE_FIELD_ALIASES = {
    "domain.suffix": "domain_suffix",
    "domain_suffix": "domain_suffix",
    "root": "domain_suffix",
    "root_domain": "domain_suffix",
    "domain": "domain_suffix",
    "host": "host",
    "hostname": "host",
    "ip": "ip",
    "url": "url",
    "title": "title",
    "app": "technologies",
    "apps": "technologies",
    "tech": "technologies",
    "technology": "technologies",
    "technologies": "technologies",
    "server": "server",
    "port": "port",
    "status": "status_code",
    "status_code": "status_code",
}


def build_target_query(root_domain: str) -> str:
    return f'domain.suffix="{root_domain}"'


def translate_provider_query(query: str, provider_name: str) -> str:
    groups = parse_online_query(query)
    if not groups:
        return query

    translated_groups = []
    for group in groups:
        translated_terms = [_translate_term(term, provider_name) for term in group]
        translated_groups.append(_join_and(provider_name, translated_terms))
    return _join_or(provider_name, translated_groups)


def parse_online_query(query: str) -> list[list[QueryTerm]]:
    value = query.strip()
    if not value or value == "*":
        return []

    groups: list[list[QueryTerm]] = []
    for raw_group in re.split(r"\s+\|\|\s+", value):
        terms: list[QueryTerm] = []
        for raw_term in re.split(r"\s+&&\s+", raw_group):
            match = ONLINE_TERM_RE.match(raw_term)
            if not match:
                raise QuerySyntaxError(f"invalid query term: {raw_term}")
            field = match.group("field").lower().replace("-", "_")
            canonical = ONLINE_FIELD_ALIASES.get(field)
            if not canonical:
                raise QuerySyntaxError(f"unsupported online field: {field}")
            terms.append(
                QueryTerm(
                    field=canonical,
                    operator=match.group("op"),
                    value=_parse_value(match.group("value").strip()),
                )
            )
        groups.append(terms)

    normalized_groups: list[list[QueryTerm]] = []
    for group in groups:
        normalized_terms = []
        for term in group:
            canonical = ONLINE_FIELD_ALIASES.get(term.field, term.field)
            normalized_terms.append(QueryTerm(field=canonical, operator=term.operator, value=term.value))
        normalized_groups.append(normalized_terms)
    return normalized_groups


def _translate_term(term: QueryTerm, provider_name: str) -> str:
    field_map = PROVIDER_FIELD_MAPS.get(provider_name)
    if not field_map:
        raise QuerySyntaxError(f"unknown provider: {provider_name}")
    provider_field = field_map.get(term.field)
    if not provider_field:
        raise QuerySyntaxError(f"{provider_name} does not support field: {term.field}")

    if provider_name == "shodan":
        return _translate_shodan_term(provider_field, term)
    return f'{provider_field}{term.operator}"{_escape_quotes(term.value)}"'


def _translate_shodan_term(provider_field: str, term: QueryTerm) -> str:
    prefix = "-" if term.operator == "!=" else ""
    value = _escape_quotes(term.value)
    if provider_field == "domain":
        if term.operator == "!=":
            return f'-domain={value}'
        return f"domain={value}"
    if provider_field in {"port"}:
        return f"{prefix}{provider_field}:{value}"
    return f'{prefix}{provider_field}:"{value}"'


def _join_and(provider_name: str, terms: list[str]) -> str:
    if provider_name == "shodan":
        return " ".join(terms)
    return " && ".join(terms)


def _join_or(provider_name: str, groups: list[str]) -> str:
    if provider_name == "shodan":
        return " OR ".join(f"({group})" for group in groups)
    return " || ".join(groups)


def _escape_quotes(value: str) -> str:
    return value.replace('"', '\\"')


def _parse_value(value: str) -> str:
    if _has_unbalanced_quotes(value):
        raise QuerySyntaxError(f"unbalanced quote in value: {value}")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _has_unbalanced_quotes(value: str) -> bool:
    return value.count('"') % 2 == 1 or value.count("'") % 2 == 1
