"""JSON-friendly serialization helpers for MCP tool payloads.

The Web API already knows how to flatten SQLModel rows for HTTP responses; MCP
needs the same behavior but without importing FastAPI. These helpers keep the
MCP payload shape aligned with the REST API so AI clients see one consistent
data model.
"""

from __future__ import annotations

from typing import Any


def dump(value: Any) -> Any:
    """Convert a SQLModel instance, dataclass or plain object into JSON data."""

    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return {key: item for key, item in value.__dict__.items() if not key.startswith("_")}
    return value


def dump_all(values) -> list[Any]:
    return [dump(value) for value in values]


def search_row_dict(row) -> dict[str, Any]:
    classification = getattr(row, "classification", None)
    return {
        "asset": dump(row.asset),
        "service": dump(row.service) if row.service else None,
        "classification": dump(classification) if classification else None,
    }


def classification_row_dict(row) -> dict[str, Any]:
    return {
        "classification": dump(row.classification),
        "asset": dump(row.asset),
        "service": dump(row.service) if row.service else None,
        "group": dump(row.group) if row.group else None,
    }


def group_row_dict(row) -> dict[str, Any]:
    return {
        "group": dump(row.group),
        "asset": dump(row.asset) if row.asset else None,
        "service": dump(row.service) if row.service else None,
    }
