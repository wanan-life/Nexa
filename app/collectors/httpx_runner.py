import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.collectors.base import CommandProgress, run_command_streaming
from app.utils.normalize import normalize_url

DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_RETRIES = 0
DEFAULT_RATE_LIMIT = 200
DEFAULT_THREADS = 100
DEFAULT_MAX_HOST_ERROR = 30
PROGRESS_INTERVAL = 10.0


@dataclass(frozen=True)
class HTTPProbeResult:
    url: str
    input_host: str | None = None
    ip: str | None = None
    cname: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    favicon_hash: str | None = None
    server: str | None = None
    cdn: str | None = None
    waf: str | None = None
    technologies: list[str] = field(default_factory=list)
    response_headers: dict[str, Any] = field(default_factory=dict)
    extracted_fqdns: list[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname or self.input_host or self.url


@dataclass(frozen=True)
class ProbeOutcome:
    """Result of one httpx invocation, including why it ended."""

    results: list[HTTPProbeResult]
    duration: float = 0.0
    timed_out: bool = False
    returncode: int = 0
    malformed_lines: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.error is None


def parse_httpx_json_line(line: str) -> HTTPProbeResult | None:
    value = line.strip()
    if not value:
        return None
    data = json.loads(value)
    url = data.get("url") or data.get("final_url") or data.get("input")
    if not url:
        return None
    normalized_url = normalize_url(str(url))

    status_code = data.get("status_code", data.get("status-code"))
    content_length = data.get("content_length", data.get("content-length"))
    favicon_hash = data.get("favicon_hash", data.get("favicon", data.get("favicon-mmh3")))
    technologies = data.get("tech") or data.get("technologies") or []
    if isinstance(technologies, str):
        technologies = [technologies]

    return HTTPProbeResult(
        url=normalized_url,
        input_host=data.get("input") or data.get("host"),
        ip=_first_string(data.get("a") or data.get("ip") or data.get("host_ip")),
        cname=_first_string(data.get("cname")),
        status_code=int(status_code) if status_code is not None else None,
        title=data.get("title"),
        content_length=int(content_length) if content_length is not None else None,
        favicon_hash=str(favicon_hash) if favicon_hash is not None else None,
        server=data.get("webserver") or data.get("server"),
        cdn=data.get("cdn_name") or data.get("cdn"),
        waf=data.get("waf"),
        technologies=[str(item) for item in technologies],
        response_headers=_parse_headers(data.get("header") or data.get("headers") or {}),
        extracted_fqdns=_parse_extracted_fqdns(data),
    )


def parse_httpx_jsonl(path: Path) -> list[HTTPProbeResult]:
    results: list[HTTPProbeResult] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            result = parse_httpx_json_line(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid httpx JSONL at line {line_number}: {exc}") from exc
        if result:
            results.append(result)
    return results


class HTTPXRunner:
    def __init__(
        self,
        binary: str = "httpx",
        timeout: int = 1800,
        request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        threads: int = DEFAULT_THREADS,
        max_host_error: int = DEFAULT_MAX_HOST_ERROR,
    ) -> None:
        self.binary = binary
        self.timeout = timeout
        self.request_timeout = request_timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.threads = threads
        self.max_host_error = max_host_error

    def build_command(self, hosts_file: Path, enrich: bool = False) -> list[str]:
        command = [
            self.binary,
            "-l",
            str(hosts_file),
            "-json",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-timeout",
            str(self.request_timeout),
            "-retries",
            str(self.retries),
            "-threads",
            str(self.threads),
            "-max-host-error",
            str(self.max_host_error),
            "-title",
            "-status-code",
            "-content-length",
            "-content-type",
            "-location",
            "-favicon",
            "-server",
            "-tech-detect",
            "-cdn",
            "-ip",
            "-cname",
            "-http2",
            "-follow-host-redirects",
        ]
        if self.rate_limit and self.rate_limit > 0:
            command.extend(["-rate-limit", str(self.rate_limit)])
        if enrich:
            command.extend(
                [
                    "-include-response-header",
                    "-extract-fqdn",
                    "-csp-probe",
                    "-tls-probe",
                ]
            )
        return command

    async def probe_file(
        self,
        hosts_file: Path,
        enrich: bool = False,
        label: str = "httpx",
        on_progress: Callable[[str], None] | None = None,
    ) -> ProbeOutcome:
        """Probe a hosts file, streaming parse results and periodic progress.

        A timeout or crash keeps the results already produced instead of losing
        the whole batch.
        """

        results: list[HTTPProbeResult] = []
        malformed = 0

        def handle_line(line: str) -> None:
            nonlocal malformed
            try:
                parsed = parse_httpx_json_line(line)
            except json.JSONDecodeError:
                malformed += 1
                return
            if parsed:
                results.append(parsed)

        def handle_progress(progress: CommandProgress) -> None:
            if not on_progress:
                return
            on_progress(
                f"{label}: {len(results)} responses, {progress.stdout_lines} lines, "
                f"{progress.elapsed:.0f}s elapsed"
            )

        command = self.build_command(hosts_file, enrich=enrich)
        result = await run_command_streaming(
            command,
            timeout=self.timeout,
            on_stdout_line=handle_line,
            on_progress=handle_progress if on_progress else None,
            progress_interval=PROGRESS_INTERVAL,
        )

        error: str | None = None
        if result.timed_out:
            error = f"timed out after {self.timeout}s"
        elif result.returncode != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or "").splitlines()
            error = f"exit code {result.returncode}" + (f": {detail[-1]}" if detail else "")

        return ProbeOutcome(
            results=results,
            duration=result.duration,
            timed_out=result.timed_out,
            returncode=result.returncode,
            malformed_lines=malformed,
            error=error,
        )


def _parse_headers(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    headers: dict[str, Any] = {}
    for line in value.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if key:
            headers[key] = raw_value.strip()
    return headers


def _parse_extracted_fqdns(data: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("extract_fqdn", "extract-fqdn", "extracted_fqdn", "extracted-fqdn", "fqdn", "fqdns"):
        _extend_strings(candidates, data.get(key))
    extracted = data.get("extracts")
    if isinstance(extracted, dict):
        for key in ("fqdn", "fqdns", "extract_fqdn", "extract-fqdn"):
            _extend_strings(candidates, extracted.get(key))
    return _dedupe_strings(candidates)


def _first_string(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            if item:
                return str(item)
        return None
    if value:
        return str(value)
    return None


def _extend_strings(target: list[str], value: Any) -> None:
    if isinstance(value, list):
        target.extend(str(item) for item in value if item)
    elif isinstance(value, str):
        target.extend(item.strip() for item in value.replace(",", "\n").splitlines() if item.strip())


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip().lower().strip(".")
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result
