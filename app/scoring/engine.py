from dataclasses import dataclass, field
from typing import Any

from app.models.asset import Asset
from app.models.service import Service
from app.scoring.rules import DEFAULT_RULES, ScoreRule


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    title: str
    score: int
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass(frozen=True)
class RiskEvaluation:
    total_score: int
    risk_level: str
    hits: list[RuleHit]
    recommended_next_steps: list[str]


class ScoringEngine:
    def __init__(self, rules: list[ScoreRule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES
        self._rules_by_id = {rule.rule_id: rule for rule in self.rules}

    def list_rules(self) -> list[ScoreRule]:
        return self.rules

    def evaluate(self, asset: Asset, service: Service | None) -> RiskEvaluation:
        hits: list[RuleHit] = []
        hits.extend(self._evaluate_asset(asset))
        if service:
            hits.extend(self._evaluate_service(asset, service))

        total = sum(hit.score for hit in hits)
        recommendations = _dedupe([hit.recommendation for hit in hits if hit.recommendation])
        return RiskEvaluation(
            total_score=total,
            risk_level=risk_level(total),
            hits=hits,
            recommended_next_steps=recommendations,
        )

    def _evaluate_asset(self, asset: Asset) -> list[RuleHit]:
        hits: list[RuleHit] = []
        host = asset.host.lower()
        env_keywords = ["dev", "test", "staging", "pre", "uat", "debug"]
        internal_keywords = ["internal", "private", "corp", "vpn", "intranet"]

        matched_env = [keyword for keyword in env_keywords if _contains_token(host, keyword)]
        if matched_env:
            hits.append(
                self._hit(
                    "keyword_env",
                    f"Hostname contains environment keyword: {', '.join(matched_env)}",
                    {"host": asset.host, "keywords": matched_env},
                )
            )

        matched_internal = [keyword for keyword in internal_keywords if _contains_token(host, keyword)]
        if matched_internal:
            hits.append(
                self._hit(
                    "internal_keyword",
                    f"Hostname contains internal keyword: {', '.join(matched_internal)}",
                    {"host": asset.host, "keywords": matched_internal},
                )
            )
        return hits

    def _evaluate_service(self, asset: Asset, service: Service) -> list[RuleHit]:
        hits: list[RuleHit] = []
        url = service.url.lower()
        title = (service.title or "").lower()
        headers = _lower_headers(service.response_headers)
        technologies = [str(item).lower() for item in service.technologies]
        text_blob = " ".join(
            [
                asset.host,
                service.url,
                service.title or "",
                service.server or "",
                " ".join(technologies),
                str(headers),
            ]
        ).lower()

        if any(keyword in url for keyword in ["swagger", "openapi", "api-docs", "api_docs"]):
            hits.append(self._hit("swagger", "Service URL suggests exposed API documentation", {"url": service.url}))

        if "graphql" in url or "graphql" in title:
            hits.append(self._hit("graphql", "Service suggests exposed GraphQL surface", {"url": service.url}))

        if service.status_code and service.status_code >= 500:
            hits.append(
                self._hit(
                    "http_500",
                    f"HTTP service returns server error status {service.status_code}",
                    {"url": service.url, "status_code": service.status_code},
                )
            )

        if any(keyword in title for keyword in ["admin", "后台", "管理系统", "管理平台", "dashboard", "console"]):
            hits.append(self._hit("admin_title", "Service title looks like an admin interface", {"title": service.title}))

        if asset.ip and not service.cdn:
            hits.append(
                self._hit(
                    "direct_ip",
                    "Service has an IP address and no CDN marker",
                    {"host": asset.host, "ip": asset.ip, "cdn": service.cdn},
                )
            )

        if "actuator" in url or "spring boot actuator" in text_blob:
            hits.append(self._hit("actuator", "Service suggests Spring Boot Actuator exposure", {"url": service.url}))

        cors_origin = headers.get("access-control-allow-origin", "")
        cors_credentials = headers.get("access-control-allow-credentials", "")
        if cors_origin == "*" or (cors_credentials.lower() == "true" and cors_origin):
            hits.append(
                self._hit(
                    "loose_cors",
                    "Service has potentially loose CORS headers",
                    {
                        "access-control-allow-origin": cors_origin,
                        "access-control-allow-credentials": cors_credentials,
                    },
                )
            )

        if "sourcemap" in text_blob or ".map" in url:
            hits.append(self._hit("sourcemap", "Service references source map indicators", {"url": service.url}))

        return hits

    def _hit(self, rule_id: str, description: str, evidence: dict[str, Any]) -> RuleHit:
        rule = self._rules_by_id[rule_id]
        return RuleHit(
            rule_id=rule.rule_id,
            title=rule.title,
            score=rule.score,
            severity=severity_for_score(rule.score),
            description=description,
            evidence=evidence,
            recommendation=rule.recommendation,
        )


def risk_level(total_score: int) -> str:
    if total_score >= 120:
        return "Critical"
    if total_score >= 80:
        return "High"
    if total_score >= 40:
        return "Medium"
    if total_score > 0:
        return "Low"
    return "Info"


def severity_for_score(score: int) -> str:
    if score >= 50:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _contains_token(value: str, keyword: str) -> bool:
    return keyword in value.replace("_", "-").split("-") or keyword in value.split(".")


def _lower_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
