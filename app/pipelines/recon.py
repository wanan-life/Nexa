import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sqlmodel import Session

from app.collectors.base import CollectedAsset, CollectorError
from app.collectors.httpx_runner import HTTPProbeResult, HTTPXRunner, parse_httpx_jsonl
from app.collectors.oneforall import OneForAllCollector, parse_oneforall_file
from app.collectors.subfinder import SubfinderCollector, parse_subfinder_file
from app.config import get_settings
from app.models.asset import Asset
from app.models.target import Target
from app.repositories import AssetRepository, ServiceRepository
from app.schemas.asset import AssetCreate
from app.schemas.service import ServiceCreate
from app.tooling import ToolResolver

ProgressCallback = Callable[[str], None]


@dataclass
class CollectorRunResult:
    name: str
    count: int = 0
    error: str | None = None


@dataclass
class ReconSummary:
    target: str
    assets_seen: int = 0
    services_seen: int = 0
    alive_assets: int = 0
    collector_results: list[CollectorRunResult] = field(default_factory=list)


def import_subdomain_file(session: Session, target: Target, file: Path, source: str) -> int:
    if target.id is None:
        raise ValueError("target must be persisted before importing assets")
    assets = _parse_subdomain_file(file, source)
    return upsert_collected_assets(session, target.id, assets)


def import_httpx_file(session: Session, target: Target, file: Path) -> int:
    if target.id is None:
        raise ValueError("target must be persisted before importing services")
    return upsert_httpx_results(session, target.id, parse_httpx_jsonl(file))


def upsert_collected_assets(session: Session, target_id: int, assets: list[CollectedAsset]) -> int:
    repo = AssetRepository(session)
    seen_hosts: set[str] = set()
    count = 0
    for item in assets:
        if item.host in seen_hosts:
            continue
        seen_hosts.add(item.host)
        repo.upsert(
            AssetCreate(
                target_id=target_id,
                host=item.host,
                source=item.source,
                ip=item.ip,
                cname=item.cname,
            )
        )
        count += 1
    return count


def upsert_httpx_results(session: Session, target_id: int, results: list[HTTPProbeResult]) -> int:
    asset_repo = AssetRepository(session)
    service_repo = ServiceRepository(session)
    count = 0
    for result in results:
        asset = asset_repo.upsert(
            AssetCreate(
                target_id=target_id,
                host=result.host,
                source="httpx",
                is_alive=True,
            )
        )
        service_repo.upsert(
            ServiceCreate(
                asset_id=asset.id,
                url=result.url,
                status_code=result.status_code,
                title=result.title,
                content_length=result.content_length,
                favicon_hash=result.favicon_hash,
                server=result.server,
                cdn=result.cdn,
                waf=result.waf,
                technologies=result.technologies,
                response_headers=result.response_headers,
            )
        )
        count += 1
    return count


async def collect_target(
    session: Session,
    target: Target,
    use_subfinder: bool = True,
    use_oneforall: bool = False,
    run_httpx: bool = True,
    tool_resolver: ToolResolver | None = None,
    continue_on_error: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> ReconSummary:
    if target.id is None:
        raise ValueError("target must be persisted before collection")

    summary = ReconSummary(target=target.name)
    collected: list[CollectedAsset] = []
    tools = tool_resolver or ToolResolver()
    _emit(progress_callback, f"Preparing target {target.name}")

    if use_subfinder:
        _emit(progress_callback, f"Running subfinder for {target.root_domain}")
        result = await _run_asset_collector(
            "subfinder",
            SubfinderCollector(
                binary=str(tools.subfinder_binary),
                config=tools.subfinder_config,
                provider_config=tools.subfinder_provider_config,
            ).collect(target.root_domain),
            continue_on_error,
        )
        summary.collector_results.append(CollectorRunResult("subfinder", len(result.assets), result.error))
        collected.extend(result.assets)
        _emit(progress_callback, _format_stage_done("subfinder", len(result.assets), result.error))
    else:
        _emit(progress_callback, "Skipping subfinder")

    if use_oneforall:
        _emit(progress_callback, f"Running OneForAll for {target.root_domain}")
        result = await _run_asset_collector(
            "oneforall",
            OneForAllCollector(
                python_binary=tools.oneforall_python,
                entrypoint=tools.oneforall_entrypoint,
                workdir=tools.oneforall_workdir,
            ).collect(target.root_domain),
            continue_on_error,
        )
        summary.collector_results.append(CollectorRunResult("oneforall", len(result.assets), result.error))
        collected.extend(result.assets)
        _emit(progress_callback, _format_stage_done("OneForAll", len(result.assets), result.error))
    else:
        _emit(progress_callback, "Skipping OneForAll")

    _emit(progress_callback, f"Upserting {len(collected)} collected assets")
    summary.assets_seen = upsert_collected_assets(session, target.id, collected)
    _emit(progress_callback, f"Asset upsert finished: {summary.assets_seen}")

    if run_httpx:
        _emit(progress_callback, "Preparing hosts for httpx")
        assets = AssetRepository(session).list_by_target(target.id)
        hosts_file = _write_hosts_file(target.name, assets)
        try:
            _emit(progress_callback, f"Running httpx for {len(assets)} assets")
            httpx_results = await HTTPXRunner(binary=str(tools.httpx_binary)).probe_file(hosts_file)
            _emit(progress_callback, f"Upserting {len(httpx_results)} HTTP services")
            summary.services_seen = upsert_httpx_results(session, target.id, httpx_results)
            summary.alive_assets = len({result.host for result in httpx_results})
            summary.collector_results.append(CollectorRunResult("httpx", summary.services_seen, None))
            _emit(progress_callback, f"httpx finished: {summary.services_seen} services")
        except (CollectorError, ValueError) as exc:
            summary.collector_results.append(CollectorRunResult("httpx", 0, str(exc)))
            _emit(progress_callback, f"httpx failed: {exc}")
            if not continue_on_error:
                raise
    else:
        _emit(progress_callback, "Skipping httpx")

    _emit(progress_callback, "Scan pipeline finished")
    return summary


@dataclass
class _AssetCollectorResult:
    assets: list[CollectedAsset]
    error: str | None = None


async def _run_asset_collector(
    name: str,
    task,
    continue_on_error: bool,
) -> _AssetCollectorResult:
    try:
        assets = await task
        return _AssetCollectorResult(assets=assets)
    except CollectorError as exc:
        if not continue_on_error:
            raise
        return _AssetCollectorResult(assets=[], error=f"{name}: {exc}")


def _parse_subdomain_file(file: Path, source: str) -> list[CollectedAsset]:
    normalized_source = source.lower()
    if normalized_source == "subfinder":
        return parse_subfinder_file(file)
    if normalized_source == "oneforall":
        return parse_oneforall_file(file)

    assets: list[CollectedAsset] = []
    for line in file.read_text(encoding="utf-8").splitlines():
        host = line.strip().split(",")[0].strip()
        if host and not host.startswith("#"):
            assets.append(CollectedAsset(host=host, source=source))
    return assets


def _write_hosts_file(target_name: str, assets: list[Asset]) -> Path:
    settings = get_settings()
    runs_dir = settings.resolved_data_dir / "runs" / target_name
    runs_dir.mkdir(parents=True, exist_ok=True)
    hosts_file = runs_dir / "httpx-hosts.txt"
    hosts_file.write_text("\n".join(asset.host for asset in assets) + "\n", encoding="utf-8")
    return hosts_file


def collect_target_sync(*args, **kwargs) -> ReconSummary:
    return asyncio.run(collect_target(*args, **kwargs))


def _emit(progress_callback: ProgressCallback | None, message: str) -> None:
    if progress_callback:
        progress_callback(message)


def _format_stage_done(name: str, count: int, error: str | None) -> str:
    if error:
        return f"{name} failed: {error}"
    return f"{name} finished: {count} assets"
