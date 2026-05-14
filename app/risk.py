from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlmodel import Session, delete, select

from app.models.asset import Asset
from app.models.risk import RiskFinding
from app.models.service import Service
from app.scoring.engine import RiskEvaluation, ScoringEngine, risk_level


@dataclass(frozen=True)
class RiskAssetSummary:
    asset: Asset
    service: Service | None
    total_score: int
    risk_level: str
    reasons: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    findings: list[RiskFinding] = field(default_factory=list)


def analyze_target_risk(session: Session, target_id: int) -> int:
    session.exec(delete(RiskFinding).where(RiskFinding.target_id == target_id))
    session.commit()

    engine = ScoringEngine()
    rows = _target_rows(session, target_id)
    count = 0
    for asset, service in rows:
        evaluation = engine.evaluate(asset, service)
        if not evaluation.hits:
            continue
        for hit in evaluation.hits:
            finding = RiskFinding(
                target_id=target_id,
                asset_id=asset.id,
                service_id=service.id if service else None,
                finding_type=hit.rule_id,
                title=hit.title,
                description=hit.description,
                severity=hit.severity,
                score=hit.score,
                evidence={
                    "rule_id": hit.rule_id,
                    "recommendation": hit.recommendation,
                    "details": hit.evidence,
                },
            )
            session.add(finding)
            count += 1
    session.commit()
    return count


def top_risk_assets(session: Session, target_id: int, limit: int = 30) -> list[RiskAssetSummary]:
    rows = _target_rows(session, target_id)
    summaries: list[RiskAssetSummary] = []
    for asset, service in rows:
        findings = _findings_for_row(session, target_id, asset.id, service.id if service else None)
        if not findings:
            continue
        total = sum(finding.score for finding in findings)
        summaries.append(
            RiskAssetSummary(
                asset=asset,
                service=service,
                total_score=total,
                risk_level=risk_level(total),
                reasons=[finding.description for finding in findings],
                recommended_next_steps=_dedupe(
                    [
                        str(finding.evidence.get("recommendation"))
                        for finding in findings
                        if finding.evidence.get("recommendation")
                    ]
                ),
                findings=findings,
            )
        )
    return sorted(summaries, key=lambda item: item.total_score, reverse=True)[:limit]


def preview_target_risk(session: Session, target_id: int, limit: int = 30) -> list[RiskAssetSummary]:
    engine = ScoringEngine()
    summaries: list[RiskAssetSummary] = []
    for asset, service in _target_rows(session, target_id):
        evaluation = engine.evaluate(asset, service)
        if not evaluation.hits:
            continue
        summaries.append(_summary_from_evaluation(asset, service, evaluation))
    return sorted(summaries, key=lambda item: item.total_score, reverse=True)[:limit]


def _target_rows(session: Session, target_id: int) -> list[tuple[Asset, Service | None]]:
    statement = (
        select(Asset, Service)
        .join(Service, Service.asset_id == Asset.id, isouter=True)
        .where(Asset.target_id == target_id)
        .order_by(Asset.host, Service.url)
    )
    return list(session.exec(statement).all())


def _findings_for_row(
    session: Session,
    target_id: int,
    asset_id: int | None,
    service_id: int | None,
) -> list[RiskFinding]:
    statement = select(RiskFinding).where(RiskFinding.target_id == target_id)
    if asset_id is not None:
        statement = statement.where(RiskFinding.asset_id == asset_id)
    if service_id is not None:
        statement = statement.where(RiskFinding.service_id == service_id)
    else:
        statement = statement.where(RiskFinding.service_id.is_(None))
    return list(session.exec(statement).all())


def _summary_from_evaluation(
    asset: Asset,
    service: Service | None,
    evaluation: RiskEvaluation,
) -> RiskAssetSummary:
    return RiskAssetSummary(
        asset=asset,
        service=service,
        total_score=evaluation.total_score,
        risk_level=evaluation.risk_level,
        reasons=[hit.description for hit in evaluation.hits],
        recommended_next_steps=evaluation.recommended_next_steps,
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
