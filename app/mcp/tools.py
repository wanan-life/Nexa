"""MCP tool registry for Nexa.

Every tool is a thin, read-mostly wrapper over the service layer that the CLI
and Web API already use (:mod:`app.query`, :mod:`app.noise`,
:mod:`app.repositories`, :mod:`app.providers`, :mod:`app.intel`). Keeping the
handlers here means there is one source of truth per capability and no
duplicated query logic.

Design rules:

* Tools are **read-only by default**. The expensive ``scan_target`` tool is only
  registered when the operator opts in with ``--allow-scan``.
* All log/progress output must go to stderr; stdout belongs to the JSON-RPC
  stream. Nothing in this module prints.
* Limits are clamped so a client cannot accidentally pull an entire database
  into its context window.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from app.config import get_settings
from app.database import create_session, init_db
from app.intel import CveExploitClient
from app.mcp.serialize import (
    classification_row_dict,
    dump,
    dump_all,
    group_row_dict,
    search_row_dict,
)
from app.noise import (
    classify_target_assets,
    get_service_classification,
    list_asset_groups,
    list_group_assets,
    list_interesting_assets,
    list_noisy_assets,
    summarize_target_noise,
)
from app.noise import (
    list_outliers as select_outlier_assets,
)
from app.pipelines.recon import collect_target_sync
from app.providers.base import OnlineAssetResult, OnlineSearchMeta
from app.providers.search import search_online_assets
from app.query import (
    QuerySyntaxError,
    list_target_apps,
    list_target_rows,
    search_target_assets,
)
from app.repositories import (
    AssetEvidenceRepository,
    AssetRepository,
    ServiceRepository,
    TargetRepository,
)

MAX_LIMIT = 200
MAX_OFFSET = 100_000


# --- shared helpers -----------------------------------------------------------


def _clamp(limit: int | None, default: int = 50, maximum: int = MAX_LIMIT) -> int:
    try:
        value = int(limit) if limit is not None else default
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def _offset(offset: int | None) -> int:
    try:
        value = int(offset) if offset is not None else 0
    except (TypeError, ValueError):
        value = 0
    return max(0, min(value, MAX_OFFSET))


def _require_target(session, target_ref: str):
    target = TargetRepository(session).get_by_ref(str(target_ref))
    if not target or target.id is None:
        raise ToolError(f"target not found: {target_ref}")
    return target


def _page(items: list[Any], start: int, size: int, total: int | None = None) -> dict[str, Any]:
    next_offset = start + len(items)
    resolved_total = total if total is not None else None
    has_more = next_offset < resolved_total if resolved_total is not None else len(items) == size
    return {
        "offset": start,
        "limit": size,
        "returned": len(items),
        "total": resolved_total,
        "next_offset": next_offset if has_more else None,
        "items": items,
    }


def _session_rows(session, target_id: int) -> list[Any]:
    return list_target_rows(session, target_id)


# --- read-only tools ----------------------------------------------------------


def list_targets() -> dict[str, Any]:
    """List every configured target with its id, root domain and program name."""

    init_db()
    with create_session() as session:
        targets = TargetRepository(session).list()
    return {"count": len(targets), "targets": dump_all(targets)}


def get_target(target_ref: str) -> dict[str, Any]:
    """Get one target by numeric id or root domain (e.g. ``1`` or ``example.com``)."""

    init_db()
    with create_session() as session:
        return dump(_require_target(session, target_ref))


def target_summary(target_ref: str) -> dict[str, Any]:
    """Summarize a target: asset/service/alive counts, source coverage and noise stats."""

    init_db()
    with create_session() as session:
        target = _require_target(session, target_ref)
        target_id = int(target.id)
        assets = AssetRepository(session).list_by_target(target_id)
        services = ServiceRepository(session).list_by_target(target_id)
        noise = summarize_target_noise(session, target_id)
        sources = AssetEvidenceRepository(session).source_counts(target_id)
    technologies: list[str] = []
    for service in services:
        for item in service.technologies or []:
            name = str(item).strip()
            if name and name not in technologies:
                technologies.append(name)
    return {
        "target": dump(target),
        "assets": len(assets),
        "alive_assets": sum(1 for asset in assets if asset.is_alive),
        "services": len(services),
        "technologies": sorted(technologies)[:MAX_LIMIT],
        "noise": {
            "groups": noise.groups,
            "classifications": noise.classifications,
            "high_noise_groups": noise.high_noise_groups,
            "outliers": noise.outliers,
        },
        "source_coverage": sources,
    }


def search_assets(target_ref: str, query: str = "*", limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Search services inside a target.

    ``query`` uses Nexa syntax: ``app="Vue.js"``, ``status=200``, ``title="admin"``,
    ``server="nginx"``, ``cdn!="cloudflare"``, combined with ``&&`` / ``||``.
    """

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        try:
            rows = search_target_assets(session, int(target.id), query or "*", limit=start + size + 1)
        except QuerySyntaxError as exc:
            raise ToolError(str(exc)) from exc
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "query": query or "*",
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": [search_row_dict(row) for row in page],
    }


def list_services(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List probed HTTP services (url, status, title, server, technologies) for a target."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = [row for row in _session_rows(session, int(target.id)) if row.service is not None]
        page = rows[start:start + size]
        total = len(rows)
    return {
        "target": target.name,
        **_page([search_row_dict(row) for row in page], start, size, total),
    }


def list_assets(target_ref: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """List host assets discovered for a target, including liveness and source."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        seen: set[int] = set()
        assets: list[Any] = []
        for row in _session_rows(session, int(target.id)):
            if row.asset.id in seen:
                continue
            if row.asset.id is not None:
                seen.add(row.asset.id)
            assets.append(row.asset)
        page = assets[start:start + size]
        total = len(assets)
    return {
        "target": target.name,
        **_page([{"asset": dump(asset)} for asset in page], start, size, total),
    }


def list_apps(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Aggregate detected technologies/components across a target's services."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_target_apps(session, int(target.id), limit=start + size + 1)
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": dump_all(page),
    }


def list_interesting(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Prioritized high-value assets (discovery value >= 45 and noise < 80)."""

    return _classification_view(target_ref, "interesting", list_interesting_assets, limit, offset)


def list_noise(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Noise/cleanup candidates (noise score >= 60), e.g. template-heavy duplicates."""

    return _classification_view(target_ref, "noise", list_noisy_assets, limit, offset)


def list_outliers(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """High-value assets hiding inside large repeated template groups."""

    return _classification_view(target_ref, "outliers", select_outlier_assets, limit, offset)


def _classification_view(target_ref, kind, loader, limit, offset) -> dict[str, Any]:
    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = loader(session, int(target.id), limit=start + size + 1)
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "view": kind,
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": [classification_row_dict(row) for row in page],
    }


def list_groups(target_ref: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List repeated service-template groups created by the noise classifier."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_asset_groups(session, int(target.id), limit=start + size + 1)
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": [group_row_dict(row) for row in page],
    }


def get_group_assets(target_ref: str, group_id: int, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """List the individual assets that make up one repeated-template group."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = list_group_assets(session, int(target.id), int(group_id), limit=start + size + 1)
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "group_id": int(group_id),
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": [classification_row_dict(row) for row in page],
    }


def inspect_service(target_ref: str, service_id: int) -> dict[str, Any]:
    """Explain one service: classification reasons, response headers and source evidence.

    This is the machine-readable form of the CLI ``why``/``inspect`` command.
    """

    init_db()
    with create_session() as session:
        target = _require_target(session, target_ref)
        target_id = int(target.id)
        row = get_service_classification(session, target_id, int(service_id))
        if not row:
            raise ToolError(f"service not found in target {target.name}: {service_id}")
        evidence = [
            item
            for item in AssetEvidenceRepository(session).list_by_target(target_id, limit=500)
            if item.service_id == service_id or item.asset_id == row.asset.id
        ]
    return {
        "target": target.name,
        "classification": classification_row_dict(row),
        "evidence": dump_all(evidence[:50]),
    }


def list_evidence(target_ref: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """List provenance evidence rows (which source/provider discovered what)."""

    init_db()
    size = _clamp(limit)
    start = _offset(offset)
    with create_session() as session:
        target = _require_target(session, target_ref)
        rows = AssetEvidenceRepository(session).list_by_target(int(target.id), limit=start + size + 1)
        page = rows[start:start + size]
        more = len(rows) > start + size
    return {
        "target": target.name,
        "offset": start,
        "limit": size,
        "returned": len(page),
        "next_offset": start + size if more else None,
        "items": dump_all(page),
    }


def source_coverage(target_ref: str) -> dict[str, Any]:
    """Count evidence rows per discovery source for a target."""

    init_db()
    with create_session() as session:
        target = _require_target(session, target_ref)
        counts = AssetEvidenceRepository(session).source_counts(int(target.id))
    return {"target": target.name, "sources": counts}


def online_search(query: str, provider: str = "all", limit: int = 30) -> dict[str, Any]:
    """Query enabled cyberspace-mapping providers (FOFA/Hunter/Shodan/ZoomEye/Quake).

    Uses Nexa query syntax; it is translated per provider automatically.
    """

    settings = get_settings()
    try:
        rows, errors, metas = search_online_assets(
            query=query,
            configs=settings.provider_configs,
            provider_name=provider or "all",
            limit=_clamp(limit, default=30, maximum=200),
        )
    except (ValueError, QuerySyntaxError) as exc:
        raise ToolError(str(exc)) from exc
    return {
        "query": query,
        "provider": provider or "all",
        "results": [_online_result(item) for item in rows],
        "errors": errors,
        "metadata": [_online_meta(item) for item in metas],
    }


def _online_result(item: OnlineAssetResult) -> dict[str, Any]:
    return {
        "provider": item.provider,
        "host": item.host,
        "ip": item.ip,
        "port": item.port,
        "url": item.url,
        "title": item.title,
        "server": item.server,
        "technologies": list(item.technologies),
    }


def _online_meta(item: OnlineSearchMeta) -> dict[str, Any]:
    return {
        "provider": item.provider,
        "total": item.total,
        "returned": item.returned,
        "message": item.message,
    }


def cve_poc(cve_id: str) -> dict[str, Any]:
    """Look up public GitHub PoC metadata for a CVE id (e.g. ``CVE-2024-12345``)."""

    settings = get_settings()
    try:
        result = CveExploitClient(settings.cve_exploit_intel).lookup(cve_id)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
    return {
        "cve_id": result.cve_id,
        "source": result.source,
        "has_public_poc": result.has_public_poc,
        "error": result.error,
        "items": dump_all(result.items),
    }


# --- opt-in tool --------------------------------------------------------------


def scan_target(
    target_ref: str,
    subfinder: bool | None = None,
    oneforall: bool | None = None,
    httpx: bool | None = None,
    online: bool | None = None,
    strict: bool = False,
    rescan_dead: bool = False,
) -> dict[str, Any]:
    """Run the full recon pipeline for a target, then re-classify noise.

    This executes bundled external tools (subfinder/OneForAll/httpx) and passive
    sources, so it can take minutes. Only available when the server was started
    with ``--allow-scan``. Omitted flags fall back to ``config/nexa.toml``.
    """

    init_db()
    defaults = get_settings().scan_tool_defaults
    with create_session() as session:
        target = _require_target(session, target_ref)
        summary = collect_target_sync(
            session,
            target,
            use_subfinder=defaults.subfinder if subfinder is None else subfinder,
            use_oneforall=defaults.oneforall if oneforall is None else oneforall,
            run_httpx=defaults.httpx if httpx is None else httpx,
            use_online_providers=defaults.online_providers if online is None else online,
            continue_on_error=not strict,
            rescan_dead=rescan_dead,
        )
        noise = classify_target_assets(session, int(target.id))
    return {
        "target": summary.target,
        "assets_seen": summary.assets_seen,
        "services_seen": summary.services_seen,
        "alive_assets": summary.alive_assets,
        "collectors": [
            {"name": item.name, "count": item.count, "error": item.error}
            for item in summary.collector_results
        ],
        "diff": {
            "new_assets": summary.diff.new_assets[:50],
            "new_services": summary.diff.new_services[:50],
            "new_technologies": summary.diff.new_technologies[:50],
            "new_sources": summary.diff.new_sources[:50],
        },
        "source_counts": summary.source_counts,
        "noise": {
            "groups": noise.groups,
            "classifications": noise.classifications,
            "high_noise_groups": noise.high_noise_groups,
            "outliers": noise.outliers,
        },
    }


# --- registration -------------------------------------------------------------

READ_ONLY_TOOLS: list[tuple[Any, str, str]] = [
    (list_targets, "list_targets", "List every configured target with id, root domain and program name."),
    (get_target, "get_target", "Get one target by numeric id or root domain such as example.com."),
    (
        target_summary,
        "target_summary",
        "Summarize a target: asset/service/alive counts, technologies, noise stats and source coverage.",
    ),
    (
        search_assets,
        "search_assets",
        'Search services inside a target with Nexa syntax, e.g. app="Vue.js" && status=200.',
    ),
    (list_services, "list_services", "List probed HTTP services (url, status, title, server, technologies)."),
    (list_assets, "list_assets", "List host assets discovered for a target, with liveness and source."),
    (list_apps, "list_apps", "Aggregate detected technologies/components across a target's services."),
    (
        list_interesting,
        "list_interesting",
        "Prioritized high-value assets to review first (discovery value >= 45, noise < 80).",
    ),
    (list_noise, "list_noise", "Noise/cleanup candidates such as duplicated storefront templates."),
    (list_outliers, "list_outliers", "High-value assets hiding inside large repeated template groups."),
    (list_groups, "list_groups", "List repeated service-template groups produced by the noise classifier."),
    (get_group_assets, "get_group_assets", "List the individual assets that belong to one template group."),
    (
        inspect_service,
        "inspect_service",
        "Explain one service: classification reasons, response headers and source evidence.",
    ),
    (list_evidence, "list_evidence", "List provenance evidence rows: which source/provider found what."),
    (source_coverage, "source_coverage", "Count evidence rows per discovery source for a target."),
    (
        online_search,
        "online_search",
        "Query enabled cyberspace-mapping providers (FOFA/Hunter/Shodan/ZoomEye/360 Quake).",
    ),
    (cve_poc, "cve_poc", "Look up public GitHub PoC metadata for a CVE id."),
]


def register_tools(server: MCPServer, *, enable_scan: bool = False) -> None:
    """Attach Nexa tools to an ``MCPServer`` instance."""

    for handler, name, description in READ_ONLY_TOOLS:
        server.add_tool(handler, name=name, description=description)
    if enable_scan:
        server.add_tool(
            scan_target,
            name="scan_target",
            description=(
                "Run the full recon pipeline for a target (subfinder/OneForAll/CT/Wayback/httpx) "
                "and re-classify noise. Slow: can take minutes."
            ),
        )
