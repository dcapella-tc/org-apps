"""CAL Document Analysis helpers for summarizing Polarity enrichment text."""

from __future__ import annotations

from typing import Any

import requests

FEATURE_APPS = 'alias,ioc,textsummarize,attack,textindustry'
DEFAULT_CAL_HOST = 'cal.threatconnect.com'
MAX_DOC_CHARS = 100_000


def format_description(summary: str | None, bullets: list[str] | None) -> str:
    """Build Description HTML from summary + bullets (playbook JMES shape)."""
    parts: list[str] = []
    bullet_list = [str(b) for b in (bullets or []) if b]
    if bullet_list:
        parts.append('<ul><li>' + '</li><li>'.join(bullet_list) + '</li></ul>')
    if summary:
        parts.append(str(summary))
    return ''.join(parts)


def parse_app_data(app_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract summary, bullets, and tags from CAL appData rows."""
    summaries: list[str] = []
    bullets: list[str] = []
    tags: list[str] = []
    seen_tags: set[str] = set()

    for row in app_data or []:
        app = row.get('app')
        if app == 'TextSummarizer':
            summary = row.get('summary')
            if summary:
                summaries.append(str(summary))
            for bullet in row.get('bullets') or []:
                if bullet:
                    bullets.append(str(bullet))
        elif app == 'TextIndustrializer':
            industry = row.get('industry', [])
            if isinstance(industry, str):
                industry = [industry]
            for name in industry or []:
                if name and name not in seen_tags:
                    seen_tags.add(name)
                    tags.append(str(name))

        if row.get('objectType') == 'attack pattern':
            object_id = row.get('objectId')
            if object_id and object_id not in seen_tags:
                seen_tags.add(object_id)
                tags.append(str(object_id))

    summary = '<br>'.join(summaries) if summaries else None
    return {
        'summary': summary,
        'bullets': bullets,
        'tags': tags,
        'raw_app_data': app_data or [],
    }


def _auth_token(cal_token: Any) -> str:
    """Unwrap Sensitive wrappers when present."""
    if hasattr(cal_token, 'value'):
        return str(cal_token.value)
    return str(cal_token)


def analyze_document(
    text: str,
    *,
    cal_token: Any,
    cal_timestamp: Any,
    cal_host: str = DEFAULT_CAL_HOST,
    log: Any = None,
) -> dict[str, Any]:
    """POST text to CAL document analyze; return summary, bullets, and tags."""
    doc = (text or '')[:MAX_DOC_CHARS]
    host = (cal_host or DEFAULT_CAL_HOST).removeprefix('https://').removeprefix('http://').rstrip(
        '/'
    )
    url = f'https://{host}/helix/document/v1/analyze'
    params = {
        'source': 'playbooks',
        'apps': FEATURE_APPS,
        'output': 'clean',
    }
    documents = [
        {
            'name': 'Playbook Document',
            'text': doc,
            'sourceId': 'http://threatconnect.com/playbooks',
            'shareable': 1,
        }
    ]
    headers = {
        'Authorization': _auth_token(cal_token),
        'Timestamp': str(cal_timestamp),
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    response = requests.post(url, params=params, json=documents, headers=headers, timeout=120)
    if log is not None:
        log.debug('CAL document analyze status=%s', response.status_code)
    if response.status_code == 429:
        raise RuntimeError('Too many CAL document analysis requests in the last 24 hours.')
    response.raise_for_status()
    payload = response.json() or []
    if not isinstance(payload, list) or not payload:
        return parse_app_data([])
    app_data = payload[0].get('appData') or []
    return parse_app_data(app_data)
