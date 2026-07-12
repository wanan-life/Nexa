from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.config import get_settings
from app.database import create_session
from app.noise import classify_target_assets
from app.pipelines.recon import collect_target_sync
from app.repositories import TargetRepository


@dataclass
class WebJob:
    id: str
    kind: str
    target: str
    status: str = "queued"
    progress: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "progress": self.progress[-80:],
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


_jobs: dict[str, WebJob] = {}
_lock = threading.Lock()


def get_job(job_id: str) -> WebJob | None:
    with _lock:
        return _jobs.get(job_id)


def start_scan_job(
    target_ref: str,
    *,
    use_subfinder: bool | None = None,
    use_oneforall: bool | None = None,
    run_httpx: bool | None = None,
    use_online_providers: bool | None = None,
    strict: bool = False,
) -> WebJob:
    job = WebJob(id=str(uuid.uuid4()), kind="scan", target=target_ref)
    with _lock:
        _jobs[job.id] = job
    thread = threading.Thread(
        target=_run_scan_job,
        args=(job.id, target_ref, use_subfinder, use_oneforall, run_httpx, use_online_providers, strict),
        daemon=True,
    )
    thread.start()
    return job


def _run_scan_job(
    job_id: str,
    target_ref: str,
    use_subfinder: bool | None,
    use_oneforall: bool | None,
    run_httpx: bool | None,
    use_online_providers: bool | None,
    strict: bool,
) -> None:
    _update_job(job_id, status="running", message="Starting scan pipeline")
    try:
        resolved_subfinder, resolved_oneforall, resolved_httpx, resolved_online = _resolve_scan_tools(
            use_subfinder,
            use_oneforall,
            run_httpx,
            use_online_providers,
        )
        with create_session() as session:
            target = TargetRepository(session).get_by_ref(target_ref)
            if not target or target.id is None:
                raise ValueError(f"target not found: {target_ref}")
            summary = collect_target_sync(
                session,
                target,
                use_subfinder=resolved_subfinder,
                use_oneforall=resolved_oneforall,
                run_httpx=resolved_httpx,
                use_online_providers=resolved_online,
                continue_on_error=not strict,
                progress_callback=lambda message: _update_job(job_id, message=message),
            )
            _update_job(job_id, message="Classifying asset groups and noise")
            noise_summary = classify_target_assets(session, target.id)
        _update_job(
            job_id,
            status="completed",
            result={
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
                    "groups": noise_summary.groups,
                    "classifications": noise_summary.classifications,
                    "high_noise_groups": noise_summary.high_noise_groups,
                    "outliers": noise_summary.outliers,
                },
            },
            message="Scan completed",
        )
    except Exception as exc:
        _update_job(job_id, status="failed", error=str(exc), message=f"Scan failed: {exc}")


def _resolve_scan_tools(
    use_subfinder: bool | None,
    use_oneforall: bool | None,
    run_httpx: bool | None,
    use_online_providers: bool | None,
) -> tuple[bool, bool, bool, bool]:
    defaults = get_settings().scan_tool_defaults
    return (
        defaults.subfinder if use_subfinder is None else use_subfinder,
        defaults.oneforall if use_oneforall is None else use_oneforall,
        defaults.httpx if run_httpx is None else run_httpx,
        defaults.online_providers if use_online_providers is None else use_online_providers,
    )


def _update_job(
    job_id: str,
    *,
    status: str | None = None,
    message: str | None = None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        if status:
            job.status = status
        if message:
            job.progress.append(message)
        if result is not None:
            job.result = result
        if error is not None:
            job.error = error
        job.updated_at = datetime.now(UTC)
