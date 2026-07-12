def infer_technologies(headers: dict[str, object], body_sample: str = "") -> list[str]:
    """Infer lightweight technology labels from response headers/body snippets."""

    labels: list[str] = []
    normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    header_text = " ".join(f"{key}: {value}" for key, value in normalized_headers.items()).lower()
    body = body_sample.lower()

    if "x-nextjs-cache" in normalized_headers:
        labels.append("Next.js")
    if "next-router-state-tree" in header_text or "next-router-prefetch" in header_text:
        labels.append("Next.js App Router")
    if "rsc" in header_text or "react-server" in header_text:
        labels.append("React Server Components")
    if normalized_headers.get("server", "").lower() == "jfe":
        labels.append("JD JFE Gateway")
    if "x-powered-by" in normalized_headers:
        powered_by = normalized_headers["x-powered-by"].strip()
        if powered_by:
            labels.append(powered_by)
    if "x-envoy" in header_text or "envoy" in normalized_headers.get("server", ""):
        labels.append("Envoy")
    if "x-backend" in header_text or "x-request-id" in header_text:
        labels.append("Gateway")
    if "__next_data__" in body:
        labels.append("Next.js")
    return _dedupe(labels)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            result.append(normalized)
    return result
