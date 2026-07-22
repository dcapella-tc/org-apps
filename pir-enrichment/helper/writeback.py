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


def add_enrichment_tag(
    tc_session: Any,
    indicator_id: int | str,
    indicator: dict[str, Any],
) -> None:
    """Add the enrichment:polarity tag and associated group ids to the indicator."""
    body = {
        'tags': {
            'data': [
                {'name': ENRICHMENT_TAG},
            ]
        },
        'associatedGroups': associated_groups_body(indicator),
    }
    response = tc_session.put(f'/v3/indicators/{indicator_id}', json=body)
    response.raise_for_status()
