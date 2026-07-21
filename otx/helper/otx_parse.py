"""Parse OTX API JSON responses into pulse lists."""

from __future__ import annotations

import json
from typing import Any


def parse_response_json(response: Any) -> dict[str, Any]:
    """Parse an HTTP response body as JSON and return a dict.

    Accepts a response-like object with ``.json()`` or ``.content`` / ``.text``.
    """
    if hasattr(response, 'json') and callable(response.json):
        try:
            data = response.json()
            if isinstance(data, dict):
                return data
            return {'results': data if isinstance(data, list) else [data]}
        except (ValueError, TypeError, json.JSONDecodeError):
            pass

    raw: str | bytes = ''
    if hasattr(response, 'content') and response.content is not None:
        raw = response.content
    elif hasattr(response, 'text') and response.text is not None:
        raw = response.text
    else:
        raw = str(response)

    if isinstance(raw, bytes):
        text = raw.decode('utf-8')
    else:
        text = str(raw)

    data = json.loads(text)
    if isinstance(data, dict):
        return data
    return {'results': data if isinstance(data, list) else [data]}


def extract_pulses(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Extract the pulse list from an OTX payload (``results`` or ``list`` key)."""
    if not payload or not isinstance(payload, dict):
        return []

    for key in ('results', 'list'):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    return []


def has_next_page(payload: dict[str, Any] | None) -> bool:
    """Return True if the payload indicates another page is available."""
    if not payload or not isinstance(payload, dict):
        return False
    for key in ('next', 'next_url'):
        value = payload.get(key)
        if value:
            return True
    return False


def merge_page_payloads(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine paginated OTX responses into one inspection-friendly payload."""
    all_pulses: list[dict[str, Any]] = []
    for page in pages:
        all_pulses.extend(extract_pulses(page))

    count = len(all_pulses)
    if pages:
        # Prefer API-reported count when present on the first page.
        first = pages[0]
        api_count = first.get('count')
        if isinstance(api_count, int):
            count = api_count

    return {
        'count': count,
        'results': all_pulses,
        'pages': len(pages),
    }
