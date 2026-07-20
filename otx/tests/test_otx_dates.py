"""Tests for helper.otx_dates."""

from datetime import UTC, datetime, timedelta

import pytest

from helper.otx_dates import (
    default_last_modified,
    format_last_modified_cursor,
    format_modified_since,
    parse_last_modified_input,
    resolve_last_modified,
)


def test_default_last_modified_is_30_days():
    now = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)
    result = default_last_modified(now=now)
    assert result == now - timedelta(days=30)


def test_resolve_last_modified_none_uses_default():
    now = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)
    result = resolve_last_modified(None, now=now)
    assert result == now - timedelta(days=30)


def test_resolve_last_modified_naive_assumes_utc():
    naive = datetime(2026, 7, 18, 8, 30, 0)
    result = resolve_last_modified(naive)
    assert result.tzinfo == UTC
    assert result.replace(tzinfo=None) == naive


def test_format_modified_since():
    dt = datetime(2026, 7, 18, 8, 30, 15, tzinfo=UTC)
    assert format_modified_since(dt) == '2026-07-18T08:30:15'


def test_format_last_modified_cursor():
    dt = datetime(2026, 7, 18, 8, 30, 15, tzinfo=UTC)
    assert format_last_modified_cursor(dt) == '2026-07-18T08:30:15Z'


def test_parse_last_modified_input_empty():
    assert parse_last_modified_input('') is None
    assert parse_last_modified_input('   ') is None
    assert parse_last_modified_input(None) is None


def test_parse_last_modified_input_iso_z():
    result = parse_last_modified_input('2026-07-18T08:30:15Z')
    assert result == datetime(2026, 7, 18, 8, 30, 15, tzinfo=UTC)


def test_parse_last_modified_input_relative_30_days_ago():
    before = datetime.now(tz=UTC) - timedelta(days=30, seconds=5)
    result = parse_last_modified_input('30 days ago')
    after = datetime.now(tz=UTC) - timedelta(days=30, seconds=-5)
    assert result is not None
    assert before <= result <= after


def test_parse_last_modified_input_invalid_raises():
    with pytest.raises(ValueError, match='Invalid last_modified'):
        parse_last_modified_input('not-a-date-xyz')
