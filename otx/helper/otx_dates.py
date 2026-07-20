"""Resolve and format OTX last_modified / modified_since timestamps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tcex.util.datetime_operation import DatetimeOperation


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


def format_last_run_cursor(value: datetime) -> str:
    """Format a datetime for persistence via ``results_tc`` (ISO-8601 UTC with Z)."""
    if value.tzinfo is None:
        resolved = value.replace(tzinfo=UTC)
    else:
        resolved = value.astimezone(UTC)
    return resolved.strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_last_run_input(value: str | None) -> datetime | None:
    """Parse an optional last_run app input.

    Accepts:
    - Empty / whitespace → ``None`` (caller uses default 30-day lookback)
    - ISO-8601 datetimes (e.g. ``2026-07-20T12:00:00Z``)
    - Relative expressions (e.g. ``30 days ago``) via TcEx ``any_to_datetime``

    Raises:
        ValueError: When the value cannot be parsed as a datetime.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # Prefer ISO first for stable cursor values from results_tc.
    try:
        normalized = text.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        pass

    try:
        arrow_dt = DatetimeOperation.any_to_datetime(text, tz='UTC')
    except Exception as exc:
        raise ValueError(
            f'Invalid last_run value "{text}". '
            'Use an ISO datetime (e.g. 2026-07-20T12:00:00Z) '
            'or a relative expression (e.g. 30 days ago).'
        ) from exc

    # Arrow → datetime (timezone-aware UTC).
    as_datetime = arrow_dt.datetime
    if as_datetime.tzinfo is None:
        return as_datetime.replace(tzinfo=UTC)
    return as_datetime.astimezone(UTC)
