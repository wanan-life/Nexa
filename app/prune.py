from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, delete, select

from app.models.api_endpoint import APIEndpoint
from app.models.asset import Asset
from app.models.asset_group import AssetClassification, AssetGroup
from app.models.evidence import AssetEvidence
from app.models.fingerprint import Fingerprint
from app.models.jsfile import JSFile
from app.models.risk import RiskFinding
from app.models.service import Service
from app.query import SearchRow, search_target_assets


@dataclass(frozen=True)
class PrunePreview:
    rows: list[SearchRow]
    service_ids: set[int]
    asset_ids: set[int]

    @property
    def service_count(self) -> int:
        return len(self.service_ids)

    @property
    def asset_count(self) -> int:
        return len(self.asset_ids)


@dataclass(frozen=True)
class PruneResult:
    services_deleted: int
    assets_deleted: int


def preview_prune(session: Session, target_id: int, query: str, limit: int = 50) -> PrunePreview:
    if not query.strip():
        raise ValueError("drop query cannot be empty")
    rows = search_target_assets(session, target_id, query, limit=10_000)
    service_ids = {row.service.id for row in rows if row.service and row.service.id is not None}
    asset_ids = {row.asset.id for row in rows if row.asset.id is not None}
    return PrunePreview(rows=rows[:limit], service_ids=service_ids, asset_ids=asset_ids)


def prune_query(session: Session, target_id: int, query: str) -> PruneResult:
    preview = preview_prune(session, target_id, query, limit=10_000)
    service_ids = set(preview.service_ids)
    candidate_asset_ids = set(preview.asset_ids)

    if service_ids:
        _delete_service_children(session, service_ids)
        session.exec(delete(Service).where(Service.id.in_(service_ids)))

    assets_to_delete = _orphaned_or_service_free_assets(session, target_id, candidate_asset_ids, service_ids)
    if assets_to_delete:
        _delete_asset_children(session, assets_to_delete)
        session.exec(delete(Asset).where(Asset.id.in_(assets_to_delete)))

    session.exec(delete(AssetClassification).where(AssetClassification.target_id == target_id))
    session.exec(delete(AssetGroup).where(AssetGroup.target_id == target_id))
    session.commit()
    return PruneResult(services_deleted=len(service_ids), assets_deleted=len(assets_to_delete))


def preview_prune_group(session: Session, target_id: int, group_id: int, limit: int = 50) -> PrunePreview:
    rows = _group_search_rows(session, target_id, group_id)
    service_ids = {row.service.id for row in rows if row.service and row.service.id is not None}
    asset_ids = {row.asset.id for row in rows if row.asset.id is not None}
    return PrunePreview(rows=rows[:limit], service_ids=service_ids, asset_ids=asset_ids)


def prune_group(session: Session, target_id: int, group_id: int) -> PruneResult:
    preview = preview_prune_group(session, target_id, group_id, limit=10_000)
    service_ids = set(preview.service_ids)
    candidate_asset_ids = set(preview.asset_ids)

    if service_ids:
        _delete_service_children(session, service_ids)
        session.exec(delete(Service).where(Service.id.in_(service_ids)))

    assets_to_delete = _orphaned_or_service_free_assets(session, target_id, candidate_asset_ids, service_ids)
    if assets_to_delete:
        _delete_asset_children(session, assets_to_delete)
        session.exec(delete(Asset).where(Asset.id.in_(assets_to_delete)))

    session.exec(delete(AssetClassification).where(AssetClassification.target_id == target_id))
    session.exec(delete(AssetGroup).where(AssetGroup.target_id == target_id))
    session.commit()
    return PruneResult(services_deleted=len(service_ids), assets_deleted=len(assets_to_delete))


def _group_search_rows(session: Session, target_id: int, group_id: int) -> list[SearchRow]:
    statement = (
        select(AssetClassification, Asset, Service)
        .join(Asset, Asset.id == AssetClassification.asset_id)
        .join(Service, Service.id == AssetClassification.service_id)
        .where(AssetClassification.target_id == target_id)
        .where(AssetClassification.group_id == group_id)
        .order_by(Asset.host)
    )
    return [
        SearchRow(asset=asset, service=service, classification=classification)
        for classification, asset, service in session.exec(statement).all()
    ]


def _delete_service_children(session: Session, service_ids: set[int]) -> None:
    for model in (APIEndpoint, Fingerprint, JSFile):
        session.exec(delete(model).where(model.service_id.in_(service_ids)))
    session.exec(delete(AssetEvidence).where(AssetEvidence.service_id.in_(service_ids)))
    session.exec(delete(RiskFinding).where(RiskFinding.service_id.in_(service_ids)))
    session.exec(delete(AssetClassification).where(AssetClassification.service_id.in_(service_ids)))


def _delete_asset_children(session: Session, asset_ids: set[int]) -> None:
    session.exec(delete(AssetEvidence).where(AssetEvidence.asset_id.in_(asset_ids)))
    session.exec(delete(RiskFinding).where(RiskFinding.asset_id.in_(asset_ids)))
    session.exec(delete(AssetClassification).where(AssetClassification.asset_id.in_(asset_ids)))


def _orphaned_or_service_free_assets(
    session: Session,
    target_id: int,
    candidate_asset_ids: set[int],
    deleted_service_ids: set[int],
) -> set[int]:
    assets_to_delete: set[int] = set()
    for asset_id in candidate_asset_ids:
        statement = select(Service.id).where(Service.asset_id == asset_id).limit(1)
        remaining_service_id = session.exec(statement).first()
        if remaining_service_id is None or remaining_service_id in deleted_service_ids:
            asset = session.get(Asset, asset_id)
            if asset and asset.target_id == target_id:
                assets_to_delete.add(asset_id)
    return assets_to_delete
