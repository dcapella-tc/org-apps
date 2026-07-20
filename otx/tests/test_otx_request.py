"""Tests for helper.otx_request."""

from datetime import UTC, datetime

from helper.otx_request import (
    build_auth_headers,
    build_subscribed_params,
    build_subscribed_path,
)


def test_build_auth_headers():
    headers = build_auth_headers('secret')
    assert headers['X-OTX-API-KEY'] == 'secret'
    assert headers['Accept'] == 'application/json'


def test_build_subscribed_params_and_path():
    last_modified = datetime(2026, 7, 18, 8, 30, 0, tzinfo=UTC)
    params = build_subscribed_params(last_modified, page=2, limit=50)
    assert params['modified_since'] == '2026-07-18T08:30:00'
    assert params['page'] == 2
    assert params['limit'] == 50

    path = build_subscribed_path(last_modified, page=2, limit=50)
    assert path.startswith('/pulses/subscribed?')
    assert 'modified_since=2026-07-18T08%3A30%3A00' in path or 'modified_since=2026-07-18T08:30:00' in path
    assert 'page=2' in path
    assert 'limit=50' in path
