"""Fetch PIR-linked indicators and check enrichment tags."""

from __future__ import annotations

from typing import Any

ENRICHMENT_TAG = 'enrichment:polarity'


def has_enrichment_tag(indicator: dict[str, Any]) -> bool:
    """Return True if the indicator already has the enrichment:polarity tag."""
    tags = (indicator.get('tags') or {}).get('data') or []
    return any(tag.get('name') == ENRICHMENT_TAG for tag in tags)


def fetch_for_pir(
    tc_session: Any,
    pir_id: str,
    *,
    owner: str,
    result_limit: int = 1000,
) -> list[dict[str, Any]]:
    """GET indicators associated with an Intel Requirement.

    Uses TQL ``hasGroup(hasIntelRequirement(id=...))``, sorted by calScore DESC.
    """
    params = {
        'tql': f'hasGroup(hasIntelRequirement(id={pir_id})) and not hasIntelRequirement(id={pir_id})',
        'sorting': 'calScore DESC',
        'fields': 'tags',
        'resultLimit': result_limit,
    }
    response = tc_session.get('/v3/indicators', params=params)
    response.raise_for_status()
    return list((response.json() or {}).get('data') or [])
