from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.collectors.base import CollectedAsset
from app.utils.normalize import normalize_host


@dataclass(frozen=True)
class PassiveCollectionResult:
    name: str
    assets: list[CollectedAsset] = field(default_factory=list)
    error: str | None = None


class CTLogCollector:
    name = "ct_logs"

    async def collect(self, root_domain: str, limit: int = 500) -> PassiveCollectionResult:
        query = f"%.{root_domain}"
        url = "https://crt.sh/"
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                response = await client.get(url, params={"q": query, "output": "json"})
                response.raise_for_status()
                rows = response.json()
        except Exception as exc:
            return PassiveCollectionResult(name=self.name, error=str(exc))

        hosts: list[str] = []
        for row in rows if isinstance(rows, list) else []:
            raw_name = str(row.get("name_value") or row.get("common_name") or "")
            for candidate in raw_name.splitlines():
                host = _clean_hostname(candidate, root_domain)
                if host and host not in hosts:
                    hosts.append(host)
                if len(hosts) >= limit:
                    break
            if len(hosts) >= limit:
                break

        return PassiveCollectionResult(
            name=self.name,
            assets=[CollectedAsset(host=host, source=self.name) for host in hosts],
        )


class WaybackCollector:
    name = "wayback"

    async def collect(self, root_domain: str, limit: int = 300) -> PassiveCollectionResult:
        url = "https://web.archive.org/cdx"
        params = {
            "url": f"*.{root_domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(limit),
        }
        try:
            async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                rows = response.json()
        except Exception as exc:
            return PassiveCollectionResult(name=self.name, error=str(exc))

        hosts: list[str] = []
        for row in rows[1:] if isinstance(rows, list) else []:
            raw_url = row[0] if isinstance(row, list) and row else str(row)
            parsed_host = urlparse(raw_url).hostname or ""
            host = _clean_hostname(parsed_host, root_domain)
            if host and host not in hosts:
                hosts.append(host)
            if len(hosts) >= limit:
                break

        return PassiveCollectionResult(
            name=self.name,
            assets=[CollectedAsset(host=host, source=self.name) for host in hosts],
        )


def _clean_hostname(value: str, root_domain: str) -> str:
    normalized = normalize_host(value.replace("*.", ""))
    if not normalized:
        return ""
    return normalized if normalized == root_domain or normalized.endswith(f".{root_domain}") else ""
