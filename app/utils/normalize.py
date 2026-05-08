from urllib.parse import urlparse


def normalize_host(value: str) -> str:
    """Normalize a user-provided host, URL, or subdomain string."""

    candidate = value.strip().lower()
    if not candidate:
        raise ValueError("host cannot be empty")

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate

    return candidate.strip(".")


def normalize_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("url cannot be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.hostname:
        raise ValueError(f"invalid url: {value}")
    return candidate.rstrip("/")

