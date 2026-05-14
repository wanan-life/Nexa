from __future__ import annotations

import base64
import math
from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import ProviderConfig
from app.providers.base import OnlineAssetResult, OnlineSearchMeta, ProviderApiError, ensure_provider_ready


class BaseHttpProvider:
    name = "base"

    def __init__(self, config: ProviderConfig, timeout: float = 30.0) -> None:
        self.config = config
        self.timeout = timeout

    def search(self, query: str, limit: int) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        ensure_provider_ready(self.config)
        with httpx.Client(timeout=self.timeout) as client:
            return self._search(client, query, limit)

    def _search(
        self,
        client: httpx.Client,
        query: str,
        limit: int,
    ) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        raise NotImplementedError


class FofaProvider(BaseHttpProvider):
    name = "fofa"

    def _search(
        self,
        client: httpx.Client,
        query: str,
        limit: int,
    ) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        fields = self.config.fields or "host,ip,port,protocol,title,server,domain"
        params = {
            "email": self.config.email,
            "key": self.config.api_key,
            "qbase64": _b64(query),
            "fields": fields,
            "size": min(limit, self.config.page_size),
        }
        response = client.get(self.config.base_url, params=params)
        response.raise_for_status()
        payload = response.json()
        _raise_fofa_error(payload)
        field_names = [item.strip() for item in fields.split(",") if item.strip()]
        rows = payload.get("results") or []
        results = [_from_fofa_row(field_names, row) for row in rows[:limit]]
        return results, OnlineSearchMeta(
            provider=self.name,
            total=_as_int(payload.get("size")),
            returned=len(results),
        )


class HunterQianxinProvider(BaseHttpProvider):
    name = "hunter_qianxin"

    def _search(
        self,
        client: httpx.Client,
        query: str,
        limit: int,
    ) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        is_web = self.config.is_web if self.config.is_web is not None else 1
        page_size = min(max(1, self.config.page_size), 10)
        max_pages = max(1, math.ceil(limit / page_size))
        results: list[OnlineAssetResult] = []
        total: int | None = None
        message = ""

        for page in range(1, max_pages + 1):
            params = {
                "api-key": self.config.api_key,
                "search": _b64url(query),
                "page": page,
                "page_size": page_size,
                "is_web": is_web,
            }
            if self.config.status_code:
                params["status_code"] = self.config.status_code
            if self.config.start_time:
                params["start_time"] = self.config.start_time
            if self.config.end_time:
                params["end_time"] = self.config.end_time
            response = client.get(self.config.base_url, params=params)
            response.raise_for_status()
            payload = response.json()
            _raise_code_error(self.name, payload)
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            total = _as_int(data.get("total"))
            message = str(payload.get("msg") or "")
            rows = _nested_list(payload, "data", "arr")
            if not rows:
                break
            results.extend(_from_hunter_row(row) for row in rows if isinstance(row, dict))
            if len(results) >= limit:
                break

        results = results[:limit]
        return results, OnlineSearchMeta(
            provider=self.name,
            total=total,
            returned=len(results),
            message=message,
        )


class ShodanProvider(BaseHttpProvider):
    name = "shodan"

    def _search(
        self,
        client: httpx.Client,
        query: str,
        limit: int,
    ) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        params = {"key": self.config.api_key, "query": query, "page": 1}
        response = client.get(self.config.base_url, params=params)
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("matches") or []
        results = [_from_shodan_row(row) for row in rows[:limit] if isinstance(row, dict)]
        return results, OnlineSearchMeta(
            provider=self.name,
            total=_as_int(payload.get("total")),
            returned=len(results),
        )


class ZoomEyeProvider(BaseHttpProvider):
    name = "zoomeye"

    def _search(
        self,
        client: httpx.Client,
        query: str,
        limit: int,
    ) -> tuple[list[OnlineAssetResult], OnlineSearchMeta]:
        headers = {"API-KEY": self.config.api_key}
        params = {"q": query, "page": 1, "pagesize": min(limit, self.config.page_size)}
        response = client.get(self.config.base_url, params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("matches") or payload.get("data") or []
        results = [_from_zoomeye_row(row) for row in rows[:limit] if isinstance(row, dict)]
        return results, OnlineSearchMeta(
            provider=self.name,
            total=_as_int(payload.get("total")),
            returned=len(results),
        )


def build_provider(config: ProviderConfig) -> BaseHttpProvider:
    providers: dict[str, type[BaseHttpProvider]] = {
        "fofa": FofaProvider,
        "hunter_qianxin": HunterQianxinProvider,
        "shodan": ShodanProvider,
        "zoomeye": ZoomEyeProvider,
    }
    provider_type = providers.get(config.name)
    if not provider_type:
        raise ValueError(f"unknown online provider: {config.name}")
    return provider_type(config)


def _from_fofa_row(field_names: list[str], row: Any) -> OnlineAssetResult:
    values = row if isinstance(row, list) else [row]
    raw = dict(zip(field_names, values, strict=False))
    url = str(raw.get("host") or "")
    parsed = urlparse(url if "://" in url else f"//{url}")
    return OnlineAssetResult(
        provider="fofa",
        host=parsed.hostname or str(raw.get("domain") or ""),
        ip=str(raw.get("ip") or ""),
        port=_as_int(raw.get("port")),
        url=url,
        title=str(raw.get("title") or ""),
        server=str(raw.get("server") or ""),
        raw=raw,
    )


def _from_hunter_row(row: dict[str, Any]) -> OnlineAssetResult:
    url = str(row.get("url") or "")
    components = row.get("component") or row.get("components") or []
    technologies = _as_string_list(components)
    server = ", ".join(technologies) if technologies else str(row.get("server") or "")
    return OnlineAssetResult(
        provider="hunter_qianxin",
        host=str(row.get("domain") or row.get("host") or _hostname(url) or ""),
        ip=str(row.get("ip") or ""),
        port=_as_int(row.get("port")),
        url=url,
        title=str(row.get("web_title") or row.get("title") or ""),
        server=server,
        technologies=technologies,
        raw=row,
    )


def _from_shodan_row(row: dict[str, Any]) -> OnlineAssetResult:
    http_data = row.get("http") if isinstance(row.get("http"), dict) else {}
    hostnames = row.get("hostnames") if isinstance(row.get("hostnames"), list) else []
    product = str(row.get("product") or "")
    return OnlineAssetResult(
        provider="shodan",
        host=str(hostnames[0]) if hostnames else "",
        ip=str(row.get("ip_str") or ""),
        port=_as_int(row.get("port")),
        url=str(http_data.get("host") or ""),
        title=str(http_data.get("title") or ""),
        server=product,
        technologies=[product] if product else [],
        raw=row,
    )


def _from_zoomeye_row(row: dict[str, Any]) -> OnlineAssetResult:
    site = row.get("site") if isinstance(row.get("site"), dict) else {}
    portinfo = row.get("portinfo") if isinstance(row.get("portinfo"), dict) else {}
    url = str(site.get("url") or row.get("url") or "")
    return OnlineAssetResult(
        provider="zoomeye",
        host=str(site.get("domain") or row.get("domain") or _hostname(url) or ""),
        ip=str(row.get("ip") or ""),
        port=_as_int(portinfo.get("port") or row.get("port")),
        url=url,
        title=str(site.get("title") or row.get("title") or ""),
        server=str(portinfo.get("app") or row.get("app") or ""),
        raw=row,
    )


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _b64url(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def _raise_fofa_error(payload: dict[str, Any]) -> None:
    if payload.get("error") is True:
        message = payload.get("errmsg") or payload.get("message") or "FOFA API error"
        raise ProviderApiError(str(message))


def _raise_code_error(provider: str, payload: dict[str, Any]) -> None:
    code = payload.get("code")
    if code in {None, 200, "200"}:
        return
    message = payload.get("msg") or payload.get("message") or "API error"
    raise ProviderApiError(f"{provider} API code={code}: {message}")


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [_component_to_string(item) for item in value if _component_to_string(item)]
    return []


def _component_to_string(value: Any) -> str:
    if isinstance(value, dict):
        name = str(value.get("name") or value.get("product") or "").strip()
        version = str(value.get("version") or "").strip()
        return f"{name} {version}".strip()
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hostname(url: str) -> str:
    if not url:
        return ""
    return urlparse(url if "://" in url else f"//{url}").hostname or ""


def _nested_list(payload: dict[str, Any], *keys: str) -> list[Any]:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    return current if isinstance(current, list) else []
