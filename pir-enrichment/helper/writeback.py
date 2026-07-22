"""Write Polarity enrichment results back to ThreatConnect indicators."""

from __future__ import annotations

from typing import Any

from helper.indicators import ENRICHMENT_TAG


def associated_groups_body(indicator: dict[str, Any]) -> dict[str, Any]:
    """Return associatedGroups payload with id-only group entries."""
    groups = (indicator.get('associatedGroups') or {}).get('data') or []
    return {
        'data': [{'id': g['id']} for g in groups if g.get('id') is not None],
    }


def build_create_body(indicator: dict[str, Any], owner: str) -> dict[str, Any]:
    """Build a v3 indicator POST body from a fetched IOC."""
    tag_names: list[str] = []
    seen: set[str] = set()
    for tag in (indicator.get('tags') or {}).get('data') or []:
        name = tag.get('name')
        if not name or name in seen:
            continue
        seen.add(name)
        tag_names.append(name)
    if ENRICHMENT_TAG not in seen:
        tag_names.append(ENRICHMENT_TAG)

    body: dict[str, Any] = {
        'summary': str(indicator.get('summary') or ''),
        'type': indicator.get('type') or '',
        'ownerName': owner,
        'tags': {'data': [{'name': name} for name in tag_names]},
        'associatedGroups': associated_groups_body(indicator),
    }
    for hash_field in ('sha256', 'sha1', 'md5'):
        value = indicator.get(hash_field)
        if value:
            body[hash_field] = value
    return body


def set_description(tc_session: Any, indicator_id: int | str, content: str) -> None:
    """PUT a Description attribute on the indicator."""
    body = {
        'attributes': {
            'data': [
                {
                    'type': 'Description',
                    'value': content,
                    'default': True,
                }
            ]
        }
    }
    response = tc_session.put(f'/v3/indicators/{indicator_id}', json=body)
    response.raise_for_status()


def create_indicator(
    tc_session: Any,
    indicator: dict[str, Any],
    owner: str,
) -> int | str:
    """POST a new indicator into owner; return the created id."""
    body = build_create_body(indicator, owner)
    response = tc_session.post('/v3/indicators', json=body)
    response.raise_for_status()
    payload = response.json() or {}
    data = payload.get('data') or payload
    return data['id']
