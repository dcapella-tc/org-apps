"""Write Polarity enrichment results back to ThreatConnect indicators."""

from __future__ import annotations

from typing import Any

from helper.indicators import ENRICHMENT_TAG


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


def add_enrichment_tag(tc_session: Any, indicator_id: int | str) -> None:
    """Add the enrichment:polarity tag to the indicator."""
    body = {
        'tags': {
            'data': [
                {'name': ENRICHMENT_TAG},
            ]
        }
    }
    response = tc_session.put(f'/v3/indicators/{indicator_id}', json=body)
    response.raise_for_status()
