"""Fetch PIR-linked indicators and check enrichment tags."""

from __future__ import annotations

from typing import Any

ENRICHMENT_TAG = 'enrichment:polarity'


def has_enrichment_tag(indicator: dict[str, Any]) -> bool:
    """Return True if the indicator already has the enrichment:polarity tag."""
    tags = (indicator.get('tags') or {}).get('data') or []
    return any(tag.get('name') == ENRICHMENT_TAG for tag in tags)


def fetch_enriched_summaries(
    tc_session: Any,
    owner: str,
    *,
    result_limit: int = 1000,
) -> set[str]:
    """GET summaries already tagged enrichment:polarity in the owner."""
    params = {
        'tql': f'(ownerName in ("{owner}")) and tag = "{ENRICHMENT_TAG}"',
        'resultLimit': result_limit,
    }
    response = tc_session.get('/v3/indicators', params=params)
    response.raise_for_status()
    data = (response.json() or {}).get('data') or []
    return {str(row['summary']) for row in data if row.get('summary')}


def fetch_for_pir(
    tc_session: Any,
    pir_id: str,
    *,
    owner: str,
    result_limit: int = 1000,
    skip_summaries: set[str] | None = None,
) -> list[dict[str, Any]]:
    """GET indicators associated with an Intel Requirement.

    Uses TQL ``hasGroup(hasIntelRequirement(id=...))``, sorted by calScore DESC.
    Excludes already-enriched summaries via ``summary not in (...)`` when provided.
    """
    _ = owner  # reserved for future owner-scoped PIR queries
    tql_list = [
        f'hasGroup(hasIntelRequirement(id={pir_id}))',
        f'not hasIntelRequirement(id={pir_id})',
        'calScore > 200',
    ]
    if skip_summaries:
        quoted = ','.join(f'"{s}"' for s in sorted(skip_summaries))
        tql_list.append(f'summary not in ({quoted})')
    params = {
        'tql': ' and '.join([f'({expression})' for expression in tql_list]),
        'sorting': 'calScore DESC',
        'fields': 'tags,associatedGroups',
        'resultLimit': result_limit,
    }
    response = tc_session.get('/v3/indicators', params=params)
    response.raise_for_status()
    return list((response.json() or {}).get('data') or [])
