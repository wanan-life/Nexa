import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.collectors.base import run_command
from app.utils.normalize import normalize_url


@dataclass(frozen=True)
class HTTPProbeResult:
    url: str
    input_host: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    favicon_hash: str | None = None
    server: str | None = None
    cdn: str | None = None
    waf: str | None = None
    technologies: list[str] = field(default_factory=list)
    response_headers: dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname or self.input_host or self.url


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
        status_code=int(status_code) if status_code is not None else None,
        title=data.get("title"),
        content_length=int(content_length) if content_length is not None else None,
        favicon_hash=str(favicon_hash) if favicon_hash is not None else None,
        server=data.get("webserver") or data.get("server"),
        cdn=data.get("cdn_name") or data.get("cdn"),
        waf=data.get("waf"),
        technologies=[str(item) for item in technologies],
        response_headers=data.get("header") or data.get("headers") or {},
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
    def __init__(self, binary: str = "httpx", timeout: int = 1800) -> None:
        self.binary = binary
        self.timeout = timeout

    async def probe_file(self, hosts_file: Path) -> list[HTTPProbeResult]:
        command = [
            self.binary,
            "-l",
            str(hosts_file),
            "-json",
            "-silent",
            "-title",
            "-status-code",
            "-content-length",
            "-favicon",
            "-server",
            "-tech-detect",
            "-cdn",
            "-follow-host-redirects",
        ]
        result = await run_command(command, timeout=self.timeout)
        results: list[HTTPProbeResult] = []
        for line_number, line in enumerate(result.stdout.splitlines(), start=1):
            try:
                parsed = parse_httpx_json_line(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid httpx output at line {line_number}: {exc}") from exc
            if parsed:
                results.append(parsed)
        return results
