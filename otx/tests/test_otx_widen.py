"""Tests for helper.otx_widen."""

from datetime import UTC, datetime, timedelta

from helper.otx_widen import (
    LOOKBACK_WINDOWS,
    lookback_for_index,
    next_wider_last_modified,
    window_start_for_index,
)


def test_lookback_sequence():
    assert lookback_for_index(0) == timedelta(days=30)
    assert lookback_for_index(1) == timedelta(days=60)
    assert lookback_for_index(2) == timedelta(days=90)
    assert lookback_for_index(3) is None


def test_window_start_for_index():
    now = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)
    assert window_start_for_index(0, now=now) == now - timedelta(days=30)
    assert window_start_for_index(2, now=now) == now - timedelta(days=90)
    assert window_start_for_index(99, now=now) is None


def test_next_wider_last_modified_progresses():
    now = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)
    current = now - timedelta(days=30)
    wider = next_wider_last_modified(current, now=now)
    assert wider == now - timedelta(days=60)

    wider2 = next_wider_last_modified(wider, now=now)
    assert wider2 == now - timedelta(days=90)

    assert next_wider_last_modified(wider2, now=now) is None


def test_lookback_windows_match_plan():
    assert LOOKBACK_WINDOWS == (
        timedelta(days=30),
        timedelta(days=60),
        timedelta(days=90),
    )
