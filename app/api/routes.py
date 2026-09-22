from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.jobs import get_job, start_scan_job
from app.config import get_settings
from app.config_writer import update_provider_config
from app.database import create_session, init_db
from app.noise import (
    classify_target_assets,
    get_service_classification,
    list_asset_groups,
    list_group_assets,
    list_interesting_assets,
    list_noisy_assets,
    list_outliers,
)
from app.providers.query import PROVIDER_FIELD_MAPS, translate_provider_query
from app.providers.search import search_online_assets
from app.prune import preview_prune, preview_prune_group, prune_group, prune_query
from app.query import QuerySyntaxError, list_target_apps, list_target_rows, search_target_assets
from app.repositories import AssetEvidenceRepository, TargetRepository
from app.schemas.target import TargetCreate

router = APIRouter(prefix="/api")


class TargetPayload(BaseModel):
    name: str
    root_domain: str | None = None
    program_name: str | None = None
    scope_type: str = "in-scope"


class ScanPayload(BaseModel):
    subfinder: bool | None = None
    oneforall: bool | None = None
    httpx: bool | None = None
    online: bool | None = None
    strict: bool = False
    rescan_dead: bool = False


class OnlineSearchPayload(BaseModel):
    query: str
    provider: str = "all"
    limit: int = Field(default=30, ge=1, le=500)


class TranslatePayload(BaseModel):
    query: str
    providers: list[str] = Field(default_factory=list)


class ProviderUpdatePayload(BaseModel):
    enabled: bool | None = None
    email: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    fields: str | None = None
    page_size: int | None = Field(default=None, ge=1, le=1000)
    is_web: int | None = None
    status_code: str | None = None
    start_time: str | None = None
    end_time: str | None = None


class DropPayload(BaseModel):
    query: str
    execute: bool = False
    limit: int = Field(default=50, ge=1, le=500)


class DropGroupPayload(BaseModel):
    group_id: int
    execute: bool = False
    limit: int = Field(default=50, ge=1, le=500)


@router.get("/summary")
def summary() -> dict[str, Any]:
    init_db()
    with create_session() as session:
        targets = TargetRepository(session).list()
    settings = get_settings()
    return {
        "targets": len(targets),
        "database": settings.resolved_database_url,
        "config_path": str(settings.app_config_path),
        "web": "enabled",
    }


@router.get("/targets")
def list_targets() -> list[dict[str, Any]]:
    init_db()
    with create_session() as session:
        return [_dump(row) for row in TargetRepository(session).list()]


@router.post("/targets")
def save_target(payload: TargetPayload) -> dict[str, Any]:
    init_db()
    with create_session() as session:
        target = TargetRepository(session).create(TargetCreate(**payload.model_dump()))
        return _dump(target)


@router.get("/targets/{target_ref}")
def get_target(target_ref: str) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        return _dump(target)


@router.delete("/targets/{target_ref}")
def delete_target(target_ref: str) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        deleted = TargetRepository(session).delete_by_name(target.name)
        if not deleted:
            raise HTTPException(status_code=404, detail="target not found")
    return {"deleted": True}


@router.post("/targets/{target_ref}/scan")
def scan_target(target_ref: str, payload: ScanPayload) -> dict[str, Any]:
    with create_session() as session:
        _require_target(session, target_ref)
    job = start_scan_job(
        target_ref,
        use_subfinder=payload.subfinder,
        use_oneforall=payload.oneforall,
        run_httpx=payload.httpx,
        use_online_providers=payload.online,
        strict=payload.strict,
        rescan_dead=payload.rescan_dead,
    )
    return job.as_dict()


@router.get("/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job.as_dict()


@router.get("/targets/{target_ref}/search")
def search_target(
    target_ref: str,
    q: str = Query(default="*"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        try:
            rows = search_target_assets(session, target.id, q, limit=offset + limit)
        except QuerySyntaxError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return [_row_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/assets")
def assets(
    target_ref: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_target_rows(session, target.id)
        seen: set[int] = set()
        output = []
        for row in rows:
            if row.asset.id in seen:
                continue
            if row.asset.id is not None:
                seen.add(row.asset.id)
            output.append({"asset": _dump(row.asset)})
        return _page(output, offset, limit)


@router.get("/targets/{target_ref}/services")
def services(
    target_ref: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = [row for row in list_target_rows(session, target.id) if row.service is not None]
        return [_row_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/apps")
def apps(
    target_ref: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_target_apps(session, target.id, limit=offset + limit)
        return [_dump(row) for row in _page(rows, offset, limit)]


@router.post("/targets/{target_ref}/classify")
def classify(target_ref: str) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        result = classify_target_assets(session, target.id)
        return _dump(result)


@router.get("/targets/{target_ref}/groups")
def groups(
    target_ref: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_asset_groups(session, target.id, limit=offset + limit)
        return [_group_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/groups/{group_id}")
def group_assets(
    target_ref: str,
    group_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_group_assets(session, target.id, group_id, limit=offset + limit)
        return [_classification_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/interesting")
def interesting(
    target_ref: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_interesting_assets(session, target.id, limit=offset + limit)
        return [_classification_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/noise")
def noise(
    target_ref: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_noisy_assets(session, target.id, limit=offset + limit)
        return [_classification_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/outliers")
def outliers(
    target_ref: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_outliers(session, target.id, limit=offset + limit)
        return [_classification_dict(row) for row in _page(rows, offset, limit)]


@router.get("/targets/{target_ref}/services/{service_id}/why")
def why(target_ref: str, service_id: int) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        row = get_service_classification(session, target.id, service_id)
        if not row:
            raise HTTPException(status_code=404, detail="service classification not found")
        evidence = [
            _dump(item)
            for item in AssetEvidenceRepository(session).list_by_target(target.id, limit=500)
            if item.service_id == service_id or item.asset_id == row.asset.id
        ]
        return {"classification": _classification_dict(row), "evidence": evidence[:50]}


@router.get("/targets/{target_ref}/sources")
def sources(target_ref: str) -> dict[str, int]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        return AssetEvidenceRepository(session).source_counts(target.id)


@router.get("/targets/{target_ref}/evidence")
def evidence(
    target_ref: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = AssetEvidenceRepository(session).list_by_target(target.id, limit=offset + limit)
        return [_dump(row) for row in _page(rows, offset, limit)]


@router.post("/targets/{target_ref}/drop")
def drop(target_ref: str, payload: DropPayload) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        if payload.execute:
            result = prune_query(session, target.id, payload.query)
            classify_target_assets(session, target.id)
            return _dump(result)
        preview = preview_prune(session, target.id, payload.query, limit=payload.limit)
        return _prune_preview_dict(preview)


@router.post("/targets/{target_ref}/drop-group")
def drop_group(target_ref: str, payload: DropGroupPayload) -> dict[str, Any]:
    with create_session() as session:
        target = _require_target(session, target_ref)
        if payload.execute:
            result = prune_group(session, target.id, payload.group_id)
            classify_target_assets(session, target.id)
            return _dump(result)
        preview = preview_prune_group(session, target.id, payload.group_id, limit=payload.limit)
        return _prune_preview_dict(preview)


@router.post("/online-search")
def online_search(payload: OnlineSearchPayload) -> dict[str, Any]:
    settings = get_settings()
    try:
        rows, errors, metas = search_online_assets(
            query=payload.query,
            configs=settings.provider_configs,
            provider_name=payload.provider,
            limit=payload.limit,
        )
    except (QuerySyntaxError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "results": [_dump(row) for row in rows],
        "errors": errors,
        "metadata": [_dump(row) for row in metas],
    }


@router.post("/providers/translate")
def translate(payload: TranslatePayload) -> dict[str, str]:
    providers = payload.providers or list(PROVIDER_FIELD_MAPS)
    output: dict[str, str] = {}
    for provider in providers:
        try:
            output[provider] = translate_provider_query(payload.query, provider)
        except QuerySyntaxError as exc:
            output[provider] = f"ERROR: {exc}"
    return output


@router.get("/config/providers")
def provider_config() -> list[dict[str, Any]]:
    settings = get_settings()
    return [_provider_public_dict(row) for row in settings.provider_configs.values()]


@router.put("/config/providers/{provider}")
def update_provider(provider: str, payload: ProviderUpdatePayload) -> dict[str, Any]:
    settings = get_settings()
    settings.ensure_app_config()
    if provider not in PROVIDER_FIELD_MAPS:
        raise HTTPException(status_code=404, detail="unknown provider")
    update_provider_config(settings.app_config_path, provider, payload.model_dump(exclude_unset=True))
    get_settings.cache_clear()
    refreshed = get_settings().provider_configs.get(provider)
    if not refreshed:
        raise HTTPException(status_code=500, detail="provider config update failed")
    return _provider_public_dict(refreshed)


def _require_target(session, target_ref: str):
    target = TargetRepository(session).get_by_ref(target_ref)
    if not target or target.id is None:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def _row_dict(row) -> dict[str, Any]:
    return {
        "asset": _dump(row.asset),
        "service": _dump(row.service) if row.service else None,
        "classification": _dump(row.classification) if row.classification else None,
    }


def _group_dict(row) -> dict[str, Any]:
    return {
        "group": _dump(row.group),
        "asset": _dump(row.asset) if row.asset else None,
        "service": _dump(row.service) if row.service else None,
    }


def _classification_dict(row) -> dict[str, Any]:
    return {
        "classification": _dump(row.classification),
        "asset": _dump(row.asset),
        "service": _dump(row.service) if row.service else None,
        "group": _dump(row.group) if row.group else None,
    }


def _prune_preview_dict(preview) -> dict[str, Any]:
    return {
        "service_count": preview.service_count,
        "asset_count": preview.asset_count,
        "rows": [_row_dict(row) for row in preview.rows],
    }


def _provider_public_dict(config) -> dict[str, Any]:
    return {
        "name": config.name,
        "enabled": config.enabled,
        "base_url": config.base_url,
        "email": config.email,
        "api_key_set": bool(config.api_key),
        "fields": config.fields,
        "page_size": config.page_size,
        "is_web": config.is_web,
        "status_code": config.status_code,
        "start_time": config.start_time,
        "end_time": config.end_time,
    }


def _page(values: list[Any], offset: int, limit: int) -> list[Any]:
    return values[offset:offset + limit]


def _dump(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return {
            key: item
            for key, item in value.__dict__.items()
            if not key.startswith("_")
        }
    return value
