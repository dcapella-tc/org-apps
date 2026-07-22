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


def build_create_body(
    indicator: dict[str, Any],
    owner: str,
    description: str,
) -> dict[str, Any]:
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
        'attributes': {
            'data': [
                {
                    'type': 'Description',
                    'value': description,
                    'default': True,
                }
            ]
        },
    }
    for hash_field in ('sha256', 'sha1', 'md5'):
        value = indicator.get(hash_field)
        if value:
            body[hash_field] = value
    return body


def create_indicator(
    tc_session: Any,
    indicator: dict[str, Any],
    owner: str,
    description: str,
) -> int | str:
    """POST a new indicator into owner; return the created id."""
    body = build_create_body(indicator, owner, description)
    response = tc_session.post('/v3/indicators', json=body)
    response.raise_for_status()
    payload = response.json() or {}
    data = payload.get('data') or payload
    return data['id']
