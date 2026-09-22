from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy import func
from sqlmodel import Session, delete, select

from app.models.asset import Asset
from app.models.asset_group import AssetClassification, AssetGroup
from app.models.service import Service
from app.noise_rules import NoiseRuleSet, load_noise_rules, match_category_rules


@dataclass(frozen=True)
class NoiseSummary:
    groups: int = 0
    classifications: int = 0
    high_noise_groups: int = 0
    outliers: int = 0


@dataclass(frozen=True)
class GroupView:
    group: AssetGroup
    asset: Asset | None = None
    service: Service | None = None


@dataclass(frozen=True)
class ClassificationView:
    classification: AssetClassification
    asset: Asset
    service: Service | None
    group: AssetGroup | None


@dataclass
class _GroupBucket:
    signature: str
    services: list[tuple[Asset, Service]] = field(default_factory=list)


def classify_target_assets(session: Session, target_id: int) -> NoiseSummary:
    rules = load_noise_rules()
    _clear_existing(session, target_id)
    rows = _target_service_rows(session, target_id)
    buckets = _build_buckets(rows)
    group_by_signature: dict[str, AssetGroup] = {}
    high_noise_groups = 0

    for bucket in buckets.values():
        group = _build_group(target_id, bucket, rules)
        session.add(group)
        session.commit()
        session.refresh(group)
        group_by_signature[bucket.signature] = group
        if group.noise_level == "high":
            high_noise_groups += 1

    classifications = 0
    outliers = 0
    for asset, service in rows:
        signature = service_signature(service)
        group = group_by_signature.get(signature)
        classification = _classify_row(target_id, asset, service, group, rules)
        session.add(classification)
        classifications += 1
        if classification.outlier:
            outliers += 1

    session.commit()
    return NoiseSummary(
        groups=len(group_by_signature),
        classifications=classifications,
        high_noise_groups=high_noise_groups,
        outliers=outliers,
    )


def summarize_target_noise(session: Session, target_id: int) -> NoiseSummary:
    """Return aggregate noise-reduction counts for a target without listing rows."""

    _ensure_classified(session, target_id)
    groups = _scalar_count(
        session, select(func.count()).select_from(AssetGroup).where(AssetGroup.target_id == target_id)
    )
    high_noise_groups = _scalar_count(
        session,
        select(func.count())
        .select_from(AssetGroup)
        .where(AssetGroup.target_id == target_id)
        .where(AssetGroup.noise_level == "high"),
    )
    classifications = _scalar_count(
        session,
        select(func.count())
        .select_from(AssetClassification)
        .where(AssetClassification.target_id == target_id),
    )
    outliers = _scalar_count(
        session,
        select(func.count())
        .select_from(AssetClassification)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.outlier == True),
    )
    return NoiseSummary(
        groups=groups,
        classifications=classifications,
        high_noise_groups=high_noise_groups,
        outliers=outliers,
    )


def _scalar_count(session: Session, statement) -> int:
    value = session.exec(statement).first()
    if value is None:
        return 0
    if isinstance(value, tuple):
        value = value[0]
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def list_asset_groups(session: Session, target_id: int, limit: int = 50) -> list[GroupView]:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetGroup)
        .where(AssetGroup.target_id == target_id)
        .order_by(AssetGroup.count.desc(), AssetGroup.noise_level.desc())
        .limit(limit)
    )
    views: list[GroupView] = []
    for group in session.exec(statement).all():
        asset, service = _sample_group_service(session, group)
        views.append(GroupView(group=group, asset=asset, service=service))
    return views


def list_group_assets(session: Session, target_id: int, group_id: int, limit: int = 50) -> list[ClassificationView]:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetClassification, Asset, Service, AssetGroup)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id, isouter=True)
        .join(AssetGroup, AssetGroup.id == AssetClassification.group_id, isouter=True)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.group_id == group_id)
        .order_by(Asset.host)
        .limit(limit)
    )
    return [
        ClassificationView(classification=classification, asset=asset, service=service, group=group)
        for classification, asset, service, group in session.exec(statement).all()
    ]


def list_noisy_assets(session: Session, target_id: int, limit: int = 50) -> list[ClassificationView]:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetClassification, Asset, Service, AssetGroup)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id, isouter=True)
        .join(AssetGroup, AssetGroup.id == AssetClassification.group_id, isouter=True)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.noise_score >= 60)
        .order_by(AssetClassification.noise_score.desc(), Asset.host)
        .limit(limit)
    )
    return [
        ClassificationView(classification=classification, asset=asset, service=service, group=group)
        for classification, asset, service, group in session.exec(statement).all()
    ]


def list_outliers(session: Session, target_id: int, limit: int = 50) -> list[ClassificationView]:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetClassification, Asset, Service, AssetGroup)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id, isouter=True)
        .join(AssetGroup, AssetGroup.id == AssetClassification.group_id, isouter=True)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.outlier == True)
        .order_by(AssetClassification.discovery_value.desc(), Asset.host)
        .limit(limit)
    )
    return [
        ClassificationView(classification=classification, asset=asset, service=service, group=group)
        for classification, asset, service, group in session.exec(statement).all()
    ]


def list_interesting_assets(session: Session, target_id: int, limit: int = 50) -> list[ClassificationView]:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetClassification, Asset, Service, AssetGroup)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id, isouter=True)
        .join(AssetGroup, AssetGroup.id == AssetClassification.group_id, isouter=True)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.discovery_value >= 45)
        .where(AssetClassification.noise_score < 80)
        .order_by(
            AssetClassification.discovery_value.desc(),
            AssetClassification.noise_score,
            Asset.host,
        )
        .limit(limit)
    )
    return [
        ClassificationView(classification=classification, asset=asset, service=service, group=group)
        for classification, asset, service, group in session.exec(statement).all()
    ]


def get_service_classification(
    session: Session,
    target_id: int,
    service_id: int,
) -> ClassificationView | None:
    _ensure_classified(session, target_id)
    statement = (
        select(AssetClassification, Asset, Service, AssetGroup)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id)
        .join(AssetGroup, AssetGroup.id == AssetClassification.group_id, isouter=True)
        .where(AssetClassification.target_id == target_id)
        .where(Service.id == service_id)
        .limit(1)
    )
    row = session.exec(statement).first()
    if not row:
        return None
    classification, asset, service, group = row
    return ClassificationView(classification=classification, asset=asset, service=service, group=group)


def _ensure_classified(session: Session, target_id: int) -> None:
    existing = session.exec(select(AssetGroup.id).where(AssetGroup.target_id == target_id).limit(1)).first()
    if existing is None:
        classify_target_assets(session, target_id)


def _sample_group_service(session: Session, group: AssetGroup) -> tuple[Asset | None, Service | None]:
    if group.id is None:
        return None, None
    statement = (
        select(Asset, Service)
        .join(AssetClassification, AssetClassification.asset_id == Asset.id)
        .join(Service, Service.id == AssetClassification.service_id)
        .where(AssetClassification.group_id == group.id)
        .order_by(Asset.host)
        .limit(1)
    )
    row = session.exec(statement).first()
    if not row:
        return None, None
    return row


def _clear_existing(session: Session, target_id: int) -> None:
    session.exec(delete(AssetClassification).where(AssetClassification.target_id == target_id))
    session.exec(delete(AssetGroup).where(AssetGroup.target_id == target_id))
    session.commit()


def _target_service_rows(session: Session, target_id: int) -> list[tuple[Asset, Service]]:
    statement = (
        select(Asset, Service)
        .join(Service, Service.asset_id == Asset.id)
        .where(Asset.target_id == target_id)
        .order_by(Asset.host, Service.url)
    )
    return list(session.exec(statement).all())


def _build_buckets(rows: list[tuple[Asset, Service]]) -> dict[str, _GroupBucket]:
    buckets: dict[str, _GroupBucket] = {}
    for asset, service in rows:
        signature = service_signature(service)
        bucket = buckets.setdefault(signature, _GroupBucket(signature=signature))
        bucket.services.append((asset, service))
    return buckets


def _build_group(target_id: int, bucket: _GroupBucket, rules: NoiseRuleSet) -> AssetGroup:
    first_asset, first_service = bucket.services[0]
    _ = first_asset
    count = len(bucket.services)
    reasons = _group_reasons(bucket, rules)
    return AssetGroup(
        target_id=target_id,
        group_type="template",
        signature=bucket.signature,
        title=first_service.title,
        favicon_hash=first_service.favicon_hash,
        server=first_service.server,
        status_code=first_service.status_code,
        location=_location(first_service),
        count=count,
        sample_hosts=_sample_hosts(bucket.services),
        noise_level=_noise_level(count, reasons),
        reasons=reasons,
    )


def _classify_row(
    target_id: int,
    asset: Asset,
    service: Service,
    group: AssetGroup | None,
    rules: NoiseRuleSet,
) -> AssetClassification:
    reasons: list[str] = []
    matched_rules = match_category_rules(asset, service, rules)
    category = _category(asset, service, rules, matched_rules)
    noise = _noise_score(asset, service, group, reasons, matched_rules, rules)
    value = _discovery_value(asset, service, group, category, reasons, matched_rules, rules)
    outlier = bool(group and group.count >= 20 and value >= 60 and noise < 80)
    if outlier:
        reasons.append("大型模板组中出现疑似高价值异常资产")
    return AssetClassification(
        target_id=target_id,
        asset_id=asset.id,
        service_id=service.id,
        group_id=group.id if group else None,
        tier=_tier(value, noise),
        category=category,
        noise_score=noise,
        discovery_value=value,
        outlier=outlier,
        reasons=_dedupe(reasons),
    )


def service_signature(service: Service) -> str:
    values = [
        str(service.status_code or ""),
        _normalize_title(service.title),
        service.favicon_hash or "",
        _normalize_server(service.server),
        _normalize_location(_location(service)),
        _header_signature(service),
    ]
    raw = "|".join(values)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"svc:{digest}"


def _group_reasons(bucket: _GroupBucket, rules: NoiseRuleSet) -> list[str]:
    _, service = bucket.services[0]
    reasons = []
    count = len(bucket.services)
    title = _normalize_title(service.title)
    if count >= 100:
        reasons.append("超大规模重复服务模板")
    elif count >= 20:
        reasons.append("重复服务模板")
    if service.status_code in {301, 302, 307, 308}:
        reasons.append("重定向模板")
    if service.status_code in {403, 404, 500, 502, 503}:
        reasons.append("常见错误页或状态码模板")
    if title in rules.generic_titles:
        reasons.append("通用或空标题")
    return reasons


def _noise_level(count: int, reasons: list[str]) -> str:
    if count >= 100 or len(reasons) >= 2:
        return "high"
    if count >= 20 or reasons:
        return "medium"
    return "low"


def _noise_score(
    asset: Asset,
    service: Service,
    group: AssetGroup | None,
    reasons: list[str],
    matched_rules,
    rules: NoiseRuleSet,
) -> int:
    score = 0
    if group:
        if group.count >= 100:
            score += 45
            reasons.append(f"大规模重复资产组，共 {group.count} 个服务")
        elif group.count >= 20:
            score += 30
            reasons.append(f"重复资产组，共 {group.count} 个服务")
    if service.status_code in {301, 302, 307, 308}:
        score += 25
        reasons.append("服务仅返回重定向")
    if service.status_code in {404, 500, 502, 503}:
        score += 20
        reasons.append(f"低信息量 HTTP 状态码：{service.status_code}")
    if _normalize_title(service.title) in rules.generic_titles:
        score += 15
        reasons.append("页面使用通用或空标题")
    for matched in matched_rules:
        if matched.rule.noise_delta:
            score += matched.rule.noise_delta
        reasons.append(matched.reason)
    if _looks_numeric_or_short_host(asset.host):
        score += 10
        reasons.append("主机标签过短或主要由数字组成")
    return min(score, 100)


def _discovery_value(
    asset: Asset,
    service: Service,
    group: AssetGroup | None,
    category: str,
    reasons: list[str],
    matched_rules,
    rules: NoiseRuleSet,
) -> int:
    value = 20
    host = asset.host.lower()
    text = " ".join(
        [
            asset.host,
            service.url,
            service.title or "",
            service.server or "",
            " ".join(service.technologies or []),
        ]
    ).lower()
    matched = sorted(keyword for keyword in rules.high_value_keywords if _keyword_match(host, keyword))
    if matched:
        value += 30
        reasons.append(f"主机名包含高价值关键词：{', '.join(matched[:5])}")
    if any(keyword in text for keyword in rules.doc_keywords):
        value += 35
        reasons.append("发现 API 文档或 GraphQL 特征")
    if category in {"admin", "api", "auth", "docs"}:
        value += 20
        reasons.append(f"识别为高关注类别：{category}")
    for matched_rule in matched_rules:
        if matched_rule.rule.value_delta:
            value += matched_rule.rule.value_delta
        reasons.append(f"命中分类规则：{matched_rule.rule.category}")
    if group and group.count <= 3:
        value += 15
        reasons.append("属于少见服务模板")
    if asset.source and "," not in asset.source:
        value += 5
        reasons.append("目前仅由单一来源发现")
    return max(0, min(value, 100))


def _tier(discovery_value: int, noise_score: int) -> int:
    if discovery_value >= 70 and noise_score < 70:
        return 1
    if discovery_value >= 50 and noise_score < 85:
        return 2
    if noise_score >= 75:
        return 4
    return 3


def _category(asset: Asset, service: Service, rules: NoiseRuleSet, matched_rules) -> str:
    text = " ".join([asset.host, service.url, service.title or ""]).lower()
    if matched_rules:
        return matched_rules[0].rule.category
    if any(keyword in text for keyword in rules.doc_keywords):
        return "docs"
    if any(keyword in text for keyword in ["admin", "console", "manager", "后台", "管理"]):
        return "admin"
    if any(keyword in text for keyword in ["auth", "sso", "cas", "login", "oauth"]):
        return "auth"
    if "api" in text or service.status_code in {401, 403}:
        return "api"
    if service.status_code in {301, 302, 307, 308}:
        return "redirect"
    if service.status_code in {404, 500, 502, 503}:
        return "error"
    return "normal"


def _sample_hosts(rows: list[tuple[Asset, Service]]) -> list[str]:
    hosts = []
    for asset, _ in rows:
        if asset.host not in hosts:
            hosts.append(asset.host)
        if len(hosts) >= 5:
            break
    return hosts


def _location(service: Service) -> str:
    for key, value in service.response_headers.items():
        if str(key).lower() == "location":
            return str(value)
    return ""


def _normalize_title(title: str | None) -> str:
    value = (title or "").strip().lower()
    return re.sub(r"\s+", " ", value)[:120]


def _normalize_server(server: str | None) -> str:
    return (server or "").strip().lower()[:80]


def _normalize_location(location: str) -> str:
    if not location:
        return ""
    parsed = urlparse(location)
    if parsed.netloc:
        return f"{parsed.netloc}{parsed.path}".lower()[:120]
    return location.lower()[:120]


def _header_signature(service: Service) -> str:
    headers = {str(key).lower(): str(value).lower() for key, value in service.response_headers.items()}
    selected = []
    for key in (
        "content-type",
        "x-nextjs-cache",
        "x-powered-by",
        "vary",
        "server",
        "x-cache",
    ):
        value = headers.get(key)
        if value:
            selected.append(f"{key}={value[:80]}")
    return "|".join(selected)


def _keyword_match(value: str, keyword: str) -> bool:
    normalized = value.replace("_", "-")
    return keyword in normalized.split(".")[0].split("-") or f"{keyword}." in normalized


def _looks_numeric_or_short_host(host: str) -> bool:
    label = host.split(".")[0]
    return label.isdigit() or len(label) <= 2


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
