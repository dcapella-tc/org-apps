"""Widen the last_modified lookback window when OTX returns no pulses."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Progressive lookbacks when a fetch returns zero pulses.
LOOKBACK_WINDOWS = (
    timedelta(days=30),
    timedelta(days=60),
    timedelta(days=90),
)


def lookback_for_index(index: int) -> timedelta | None:
    """Return the lookback timedelta for a 0-based attempt index, or None if exhausted."""
    if index < 0 or index >= len(LOOKBACK_WINDOWS):
        return None
    return LOOKBACK_WINDOWS[index]


def window_start_for_index(
    index: int,
    *,
    now: datetime | None = None,
) -> datetime | None:
    """Return UTC window start for attempt ``index``, or None if no more windows."""
    lookback = lookback_for_index(index)
    if lookback is None:
        return None
    current = now if now is not None else datetime.now(tz=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current - lookback


def next_wider_last_modified(
    current_last_modified: datetime,
    *,
    now: datetime | None = None,
) -> datetime | None:
    """Return the next wider window start after ``current_last_modified``, or None.

    Finds the smallest configured lookback that starts earlier than the current
    window, then returns that window start. If already at or beyond the widest
    window, returns ``None``.
    """
    current = now if now is not None else datetime.now(tz=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    resolved = current_last_modified
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=UTC)
    else:
        resolved = resolved.astimezone(UTC)

    for lookback in LOOKBACK_WINDOWS:
        candidate = current - lookback
        # Strictly older (wider) than the current window start.
        if candidate < resolved:
            return candidate
    return None
