"""Resolve and format OTX last_modified / modified_since timestamps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


DEFAULT_LOOKBACK = timedelta(days=30)


def default_last_modified(*, now: datetime | None = None) -> datetime:
    """Return UTC now minus the default 30-day lookback."""
    current = now if now is not None else datetime.now(tz=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current - DEFAULT_LOOKBACK


def resolve_last_modified(
    last_modified: datetime | None = None,
    *,
    now: datetime | None = None,
) -> datetime:
    """Return ``last_modified`` or the default 30-day lookback window start."""
    if last_modified is None:
        return default_last_modified(now=now)
    if last_modified.tzinfo is None:
        return last_modified.replace(tzinfo=UTC)
    return last_modified.astimezone(UTC)


def format_modified_since(last_modified: datetime) -> str:
    """Format a datetime as an OTX ``modified_since`` query value (ISO-8601 UTC)."""
    resolved = resolve_last_modified(last_modified)
    return resolved.strftime('%Y-%m-%dT%H:%M:%S')


def format_last_modified_cursor(value: datetime) -> str:
    """Format a datetime for persistence via ``results_tc`` (ISO-8601 UTC with Z)."""
    if value.tzinfo is None:
        resolved = value.replace(tzinfo=UTC)
    else:
        resolved = value.astimezone(UTC)
    return resolved.strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_last_modified_input(value: str | None) -> datetime | None:
    """Parse an optional ISO datetime string from app input.

    Empty or whitespace-only values return ``None`` (use default lookback).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    normalized = text.replace('Z', '+00:00')
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
