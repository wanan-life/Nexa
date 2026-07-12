import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sqlmodel import Session

from app.collectors.base import CollectedAsset, CollectorError
from app.collectors.httpx_runner import HTTPProbeResult, HTTPXRunner, parse_httpx_jsonl
from app.collectors.oneforall import OneForAllCollector, parse_oneforall_file
from app.collectors.passive import CTLogCollector, WaybackCollector
from app.collectors.subfinder import SubfinderCollector, parse_subfinder_file
from app.config import get_settings
from app.analyzers.tech_analyzer import infer_technologies
from app.expanders import expand_from_patterns, expand_from_seeds
from app.models.asset import Asset
from app.models.service import Service
from app.models.target import Target
from app.providers.base import OnlineAssetResult
from app.providers.query import build_target_query
from app.providers.search import search_online_assets
from app.repositories import AssetEvidenceRepository, AssetRepository, AssetSeedRepository, ServiceRepository
from app.schemas.asset import AssetCreate
from app.schemas.service import ServiceCreate
from app.tooling import ToolResolver
from app.utils.normalize import normalize_host

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
    diff: "ReconDiff" = field(default_factory=lambda: ReconDiff())
    source_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class ReconDiff:
    new_assets: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    new_sources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReconSnapshot:
    assets: set[str]
    services: set[str]
    technologies: set[str]
    sources: set[str]


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
    evidence_repo = AssetEvidenceRepository(session)
    seen_hosts: set[str] = set()
    count = 0
    for item in assets:
        if item.host in seen_hosts:
            continue
        seen_hosts.add(item.host)
        asset = repo.upsert(
            AssetCreate(
                target_id=target_id,
                host=item.host,
                source=item.source,
                ip=item.ip,
                cname=item.cname,
            )
        )
        evidence_repo.upsert(
            target_id=target_id,
            asset_id=asset.id,
            source=item.source,
            query_type="hostname",
            raw_host=asset.host,
            ip=item.ip,
            confidence=_source_confidence(item.source),
        )
        count += 1
    return count


def upsert_httpx_results(session: Session, target_id: int, results: list[HTTPProbeResult]) -> int:
    asset_repo = AssetRepository(session)
    service_repo = ServiceRepository(session)
    evidence_repo = AssetEvidenceRepository(session)
    count = 0
    for result in results:
        technologies = _merge_technologies(
            result.technologies,
            infer_technologies(result.response_headers),
        )
        asset = asset_repo.upsert(
            AssetCreate(
                target_id=target_id,
                host=result.host,
                source="httpx",
                ip=result.ip,
                cname=result.cname,
                is_alive=True,
            )
        )
        service = service_repo.upsert(
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
                technologies=technologies,
                response_headers=result.response_headers,
            )
        )
        evidence_repo.upsert(
            target_id=target_id,
            asset_id=asset.id,
            service_id=service.id,
            source="httpx",
            query_type="http_probe",
            raw_host=result.host,
            raw_url=result.url,
            title=result.title,
            confidence=85,
            raw_snapshot={
                "status_code": result.status_code,
                "server": result.server,
                "technologies": technologies,
                "extracted_fqdns": result.extracted_fqdns,
            },
        )
        count += 1
    return count


async def collect_target(
    session: Session,
    target: Target,
    use_subfinder: bool = True,
    use_oneforall: bool = False,
    run_httpx: bool = True,
    use_online_providers: bool = True,
    use_passive_sources: bool = True,
    use_expanders: bool = True,
    tool_resolver: ToolResolver | None = None,
    continue_on_error: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> ReconSummary:
    if target.id is None:
        raise ValueError("target must be persisted before collection")

    summary = ReconSummary(target=target.name)
    collected: list[CollectedAsset] = []
    tools = tool_resolver or ToolResolver()
    settings = get_settings()
    before_snapshot = capture_recon_snapshot(session, target.id)
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

    if use_passive_sources and settings.scan_tool_defaults.ct_logs:
        _emit(progress_callback, f"Running CT logs for {target.root_domain}")
        result = await CTLogCollector().collect(
            target.root_domain,
            limit=settings.scan_tool_defaults.ct_limit,
        )
        summary.collector_results.append(
            CollectorRunResult(result.name, len(result.assets), result.error)
        )
        collected.extend(result.assets)
        _emit(progress_callback, _format_stage_done("CT logs", len(result.assets), result.error))
    else:
        _emit(progress_callback, "Skipping CT logs")

    if use_passive_sources and settings.scan_tool_defaults.wayback:
        _emit(progress_callback, f"Running Wayback for {target.root_domain}")
        result = await WaybackCollector().collect(
            target.root_domain,
            limit=settings.scan_tool_defaults.wayback_limit,
        )
        summary.collector_results.append(
            CollectorRunResult(result.name, len(result.assets), result.error)
        )
        collected.extend(result.assets)
        _emit(progress_callback, _format_stage_done("Wayback", len(result.assets), result.error))
    else:
        _emit(progress_callback, "Skipping Wayback")

    online_results: list[OnlineAssetResult] = []
    if use_online_providers:
        enabled_providers = [
            name for name, config in settings.provider_configs.items() if config.enabled
        ]
        if enabled_providers:
            query = build_target_query(target.root_domain)
            _emit(progress_callback, f"Running online providers for {target.root_domain}: {', '.join(enabled_providers)}")
            online_results, online_errors, online_metas = search_online_assets(
                query=query,
                configs=settings.provider_configs,
                provider_name="all",
                limit=settings.scan_tool_defaults.online_limit,
            )
            for meta in online_metas:
                summary.collector_results.append(
                    CollectorRunResult(
                        f"online:{meta.provider}",
                        meta.returned,
                        meta.message or None,
                    )
                )
            for error in online_errors:
                summary.collector_results.append(CollectorRunResult("online", 0, error))
            collected.extend(_online_results_to_assets(online_results))
            _emit(progress_callback, f"online providers finished: {len(online_results)} rows")
        else:
            _emit(progress_callback, "Skipping online providers: no provider enabled")
    else:
        _emit(progress_callback, "Skipping online providers")

    _emit(progress_callback, f"Upserting {len(collected)} collected assets")
    summary.assets_seen += upsert_collected_assets(session, target.id, collected)
    _emit(progress_callback, f"Asset upsert finished: {summary.assets_seen}")

    if use_expanders and settings.scan_tool_defaults.seed_expansion:
        seeds = AssetSeedRepository(session).list_by_target(target.id)
        if seeds:
            seed_assets = [CollectedAsset(host=seed.host, source=f"seed:{seed.source}") for seed in seeds]
            _emit(progress_callback, f"Upserting {len(seed_assets)} manual seeds")
            summary.assets_seen += upsert_collected_assets(session, target.id, seed_assets)
            expansion = expand_from_seeds(
                target.root_domain,
                seeds,
                limit=settings.scan_tool_defaults.expansion_limit,
            )
            summary.collector_results.append(CollectorRunResult(expansion.name, len(expansion.assets), None))
            _emit(progress_callback, f"Expanding from seeds: {len(expansion.assets)} candidates")
            summary.assets_seen += upsert_collected_assets(session, target.id, expansion.assets)
        else:
            _emit(progress_callback, "Skipping seed expansion: no seeds")
    else:
        _emit(progress_callback, "Skipping seed expansion")

    if use_expanders and settings.scan_tool_defaults.pattern_expansion:
        existing_assets = AssetRepository(session).list_by_target(target.id)
        expansion = expand_from_patterns(
            target.root_domain,
            existing_assets,
            limit=settings.scan_tool_defaults.expansion_limit,
        )
        summary.collector_results.append(CollectorRunResult(expansion.name, len(expansion.assets), None))
        _emit(progress_callback, f"Expanding from naming patterns: {len(expansion.assets)} candidates")
        summary.assets_seen += upsert_collected_assets(session, target.id, expansion.assets)
    else:
        _emit(progress_callback, "Skipping pattern expansion")

    if online_results:
        _emit(progress_callback, f"Upserting {len(online_results)} online provider services")
        online_services = upsert_online_results(session, target.id, online_results)
        summary.services_seen += online_services
        _emit(progress_callback, f"Online provider service upsert finished: {online_services}")

    if run_httpx:
        _emit(progress_callback, "Preparing hosts for httpx")
        assets = AssetRepository(session).list_by_target(target.id)
        try:
            _emit(progress_callback, f"Running httpx for {len(assets)} assets")
            runner = HTTPXRunner(binary=str(tools.httpx_binary), timeout=settings.scan_tool_defaults.httpx_timeout)
            httpx_results = await _probe_assets_in_batches(
                runner=runner,
                target_name=target.name,
                assets=assets,
                batch_size=settings.scan_tool_defaults.httpx_batch_size,
                progress_callback=progress_callback,
            )
            _emit(progress_callback, f"Upserting {len(httpx_results)} HTTP services")
            summary.services_seen = upsert_httpx_results(session, target.id, httpx_results)
            enrich_assets = _select_enrichment_assets(
                session,
                target.id,
                limit=settings.scan_tool_defaults.httpx_enrich_limit,
            )
            enrich_results: list[HTTPProbeResult] = []
            if enrich_assets:
                _emit(progress_callback, f"Running httpx enrichment for {len(enrich_assets)} selected assets")
                enrich_file = _write_hosts_file(target.name, enrich_assets, filename="httpx-enrich-hosts.txt")
                enrich_results = await runner.probe_file(enrich_file, enrich=True)
                summary.services_seen += upsert_httpx_results(session, target.id, enrich_results)
                summary.collector_results.append(
                    CollectorRunResult("httpx:enrich", len(enrich_results), None)
                )
            extracted_assets = upsert_httpx_extracted_fqdns(session, target.id, target.root_domain, enrich_results)
            summary.assets_seen += extracted_assets
            second_pass_services = 0
            second_pass_results: list[HTTPProbeResult] = []
            if extracted_assets:
                summary.collector_results.append(
                    CollectorRunResult("httpx:extract-fqdn", extracted_assets, None)
                )
                extracted_hosts = _recent_extracted_hosts(
                    session,
                    target.id,
                    limit=settings.scan_tool_defaults.extracted_probe_limit,
                )
                if extracted_hosts:
                    extracted_hosts_file = _write_hosts_file(
                        target.name,
                        extracted_hosts,
                        filename="httpx-extracted-hosts.txt",
                    )
                    _emit(progress_callback, f"Running httpx second pass for {len(extracted_hosts)} extracted hosts")
                    second_pass_results = await runner.probe_file(extracted_hosts_file, enrich=False)
                    second_pass_services = upsert_httpx_results(session, target.id, second_pass_results)
                    summary.services_seen += second_pass_services
                    summary.collector_results.append(
                        CollectorRunResult("httpx:second-pass", second_pass_services, None)
                    )
            summary.alive_assets = len({result.host for result in [*httpx_results, *enrich_results, *second_pass_results]})
            summary.collector_results.append(CollectorRunResult("httpx", summary.services_seen, None))
            _emit(
                progress_callback,
                f"httpx finished: {summary.services_seen} services, "
                f"{extracted_assets} extracted hosts, {second_pass_services} second-pass services",
            )
        except (CollectorError, ValueError) as exc:
            summary.collector_results.append(CollectorRunResult("httpx", 0, str(exc)))
            _emit(progress_callback, f"httpx failed: {exc}")
            if not continue_on_error:
                raise
    else:
        _emit(progress_callback, "Skipping httpx")

    _emit(progress_callback, "Scan pipeline finished")
    after_snapshot = capture_recon_snapshot(session, target.id)
    summary.diff = diff_recon_snapshots(before_snapshot, after_snapshot)
    summary.source_counts = AssetEvidenceRepository(session).source_counts(target.id)
    return summary


def capture_recon_snapshot(session: Session, target_id: int) -> ReconSnapshot:
    assets = AssetRepository(session).list_by_target(target_id)
    services = ServiceRepository(session).list_by_target(target_id)
    technologies: set[str] = set()
    for service in services:
        technologies.update(str(item).strip() for item in service.technologies if str(item).strip())
    sources = set(AssetEvidenceRepository(session).source_counts(target_id).keys())
    return ReconSnapshot(
        assets={asset.host for asset in assets},
        services={service.url for service in services},
        technologies=technologies,
        sources=sources,
    )


def diff_recon_snapshots(before: ReconSnapshot, after: ReconSnapshot) -> ReconDiff:
    return ReconDiff(
        new_assets=sorted(after.assets - before.assets),
        new_services=sorted(after.services - before.services),
        new_technologies=sorted(after.technologies - before.technologies),
        new_sources=sorted(after.sources - before.sources),
    )


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


def upsert_online_results(session: Session, target_id: int, results: list[OnlineAssetResult]) -> int:
    asset_repo = AssetRepository(session)
    service_repo = ServiceRepository(session)
    evidence_repo = AssetEvidenceRepository(session)
    count = 0
    for result in results:
        host = result.host or _host_from_url(result.url) or result.ip
        if not host:
            continue
        asset = asset_repo.upsert(
            AssetCreate(
                target_id=target_id,
                host=host,
                source=f"online:{result.provider}",
                ip=result.ip or None,
                is_alive=bool(result.url),
            )
        )
        if result.url:
            service = service_repo.upsert(
                ServiceCreate(
                    asset_id=asset.id,
                    url=result.url,
                    port=result.port,
                    title=result.title or None,
                    server=result.server or None,
                    technologies=result.technologies,
                )
            )
            evidence_repo.upsert(
                target_id=target_id,
                asset_id=asset.id,
                service_id=service.id,
                source="online",
                provider=result.provider,
                query_type="provider_result",
                raw_host=host,
                raw_url=result.url,
                ip=result.ip or None,
                port=result.port,
                title=result.title or None,
                confidence=70,
                raw_snapshot=result.raw,
            )
            count += 1
        else:
            evidence_repo.upsert(
                target_id=target_id,
                asset_id=asset.id,
                source="online",
                provider=result.provider,
                query_type="provider_result",
                raw_host=host,
                ip=result.ip or None,
                port=result.port,
                title=result.title or None,
                confidence=65,
                raw_snapshot=result.raw,
            )
    return count


def upsert_httpx_extracted_fqdns(
    session: Session,
    target_id: int,
    root_domain: str,
    results: list[HTTPProbeResult],
) -> int:
    asset_repo = AssetRepository(session)
    evidence_repo = AssetEvidenceRepository(session)
    seen_hosts: set[str] = set()
    count = 0
    for result in results:
        for raw_host in result.extracted_fqdns:
            host = normalize_host(raw_host)
            if not _host_in_scope(host, root_domain) or host in seen_hosts:
                continue
            seen_hosts.add(host)
            asset = asset_repo.upsert(
                AssetCreate(
                    target_id=target_id,
                    host=host,
                    source="httpx:extract-fqdn",
                )
            )
            evidence_repo.upsert(
                target_id=target_id,
                asset_id=asset.id,
                source="httpx:extract-fqdn",
                query_type="response_fqdn",
                raw_host=host,
                raw_url=result.url,
                confidence=70,
                raw_snapshot={"source_url": result.url},
            )
            count += 1
    return count


def _online_results_to_assets(results: list[OnlineAssetResult]) -> list[CollectedAsset]:
    assets: list[CollectedAsset] = []
    for result in results:
        host = result.host or _host_from_url(result.url) or result.ip
        if host:
            assets.append(
                CollectedAsset(
                    host=host,
                    source=f"online:{result.provider}",
                    ip=result.ip or None,
                )
            )
    return assets


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    from urllib.parse import urlparse

    return urlparse(url if "://" in url else f"//{url}").hostname or ""


def _host_in_scope(host: str, root_domain: str) -> bool:
    root = normalize_host(root_domain)
    return bool(host and root and (host == root or host.endswith(f".{root}")))


async def _probe_assets_in_batches(
    runner: HTTPXRunner,
    target_name: str,
    assets: list[Asset],
    batch_size: int,
    progress_callback: ProgressCallback | None,
) -> list[HTTPProbeResult]:
    if batch_size <= 0:
        batch_size = 2000
    results: list[HTTPProbeResult] = []
    total = len(assets)
    for index, batch in enumerate(_chunks(assets, batch_size), start=1):
        _emit(progress_callback, f"Running httpx batch {index} ({len(batch)}/{total})")
        hosts_file = _write_hosts_file(target_name, batch, filename=f"httpx-hosts-{index}.txt")
        results.extend(await runner.probe_file(hosts_file, enrich=False))
    return results


def _select_enrichment_assets(session: Session, target_id: int, limit: int) -> list[Asset]:
    if limit <= 0:
        return []
    assets = AssetRepository(session).list_by_target(target_id, alive_only=True)
    keyword_assets = [
        asset for asset in assets
        if any(keyword in asset.host.lower() for keyword in ("api", "admin", "auth", "sso", "pay", "open", "gateway"))
    ]
    selected: list[Asset] = []
    seen: set[int] = set()
    for asset in [*keyword_assets, *assets]:
        if asset.id is None or asset.id in seen:
            continue
        selected.append(asset)
        seen.add(asset.id)
        if len(selected) >= limit:
            break
    return selected


def _write_hosts_file(target_name: str, assets: list[Asset], filename: str = "httpx-hosts.txt") -> Path:
    settings = get_settings()
    runs_dir = settings.resolved_data_dir / "runs" / target_name
    runs_dir.mkdir(parents=True, exist_ok=True)
    hosts_file = runs_dir / filename
    hosts_file.write_text("\n".join(asset.host for asset in assets) + "\n", encoding="utf-8")
    return hosts_file


def _chunks(values: list[Asset], size: int):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _recent_extracted_hosts(session: Session, target_id: int, limit: int) -> list[Asset]:
    assets = [
        asset for asset in AssetRepository(session).list_by_target(target_id)
        if "httpx:extract-fqdn" in asset.source and not asset.is_alive
    ]
    return assets[:limit]


def collect_target_sync(*args, **kwargs) -> ReconSummary:
    return asyncio.run(collect_target(*args, **kwargs))


def _emit(progress_callback: ProgressCallback | None, message: str) -> None:
    if progress_callback:
        progress_callback(message)


def _format_stage_done(name: str, count: int, error: str | None) -> str:
    if error:
        return f"{name} failed: {error}"
    return f"{name} finished: {count} assets"


def _source_confidence(source: str) -> int:
    if source.startswith("seed:"):
        return 90
    if source in {"ct_logs", "subfinder", "oneforall"}:
        return 75
    if source == "wayback":
        return 65
    if source in {"seed_expansion", "pattern_expansion"}:
        return 40
    return 50


def _merge_technologies(primary: list[str], inferred: list[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for item in [*primary, *inferred]:
        normalized = str(item).strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            values.append(normalized)
    return values
