"""Build OTX HTTP request path, query params, and auth headers."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlencode

from helper.otx_dates import format_modified_since, resolve_last_modified

SUBSCRIBED_PATH = '/pulses/subscribed'
DEFAULT_PAGE_LIMIT = 50


def build_auth_headers(api_key: str) -> dict[str, str]:
    """Return headers required for authenticated OTX API calls."""
    return {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json',
    }


def build_subscribed_params(
    last_modified: datetime,
    *,
    page: int = 1,
    limit: int = DEFAULT_PAGE_LIMIT,
) -> dict[str, str | int]:
    """Build query parameters for one page of ``/pulses/subscribed``."""
    resolved = resolve_last_modified(last_modified)
    return {
        'modified_since': format_modified_since(resolved),
        'page': page,
        'limit': limit,
    }


def build_subscribed_path(
    last_modified: datetime,
    *,
    page: int = 1,
    limit: int = DEFAULT_PAGE_LIMIT,
) -> str:
    """Return the path + query string for one subscribed-pulses page request."""
    params = build_subscribed_params(last_modified, page=page, limit=limit)
    return f'{SUBSCRIBED_PATH}?{urlencode(params)}'
