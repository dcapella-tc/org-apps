"""Polarity API helpers: integrations list, filter, and lookup."""

from __future__ import annotations

from typing import Any


def build_auth_headers(api_key: str) -> dict[str, str]:
    """Return Bearer auth headers for Polarity requests."""
    return {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/vnd.api+json',
        'Content-Type': 'application/vnd.api+json',
    }


def list_integrations(session: Any, headers: dict[str, str]) -> dict[str, Any]:
    """GET /integrations and return the JSON payload."""
    response = session.get('/integrations', headers=headers)
    response.raise_for_status()
    return response.json() or {}


def matching_ids(integrations_payload: dict[str, Any], polarity_type: str) -> list[str]:
    """Return unique integration ids that support the given Polarity entity type."""
    seen: set[str] = set()
    ids: list[str] = []
    for item in integrations_payload.get('data') or []:
        attrs = item.get('attributes') or {}
        entity_types = attrs.get('integration-entity-types') or []
        for entity in entity_types:
            if entity.get('key') != polarity_type:
                continue
            integration_id = str(entity.get('integration_id') or item.get('id') or '')
            if integration_id and integration_id not in seen:
                seen.add(integration_id)
                ids.append(integration_id)
            break
    return ids


def build_lookup_body(value: str, polarity_type: str) -> dict[str, Any]:
    """Build a JSON:API integration-lookups request body."""
    return {
        'data': {
            'type': 'integration-lookups',
            'attributes': {
                'entities': [
                    {
                        'value': value,
                        'type': polarity_type,
                    }
                ]
            },
        }
    }


def lookup_all(
    session: Any,
    headers: dict[str, str],
    integration_ids: list[str],
    value: str,
    polarity_type: str,
    *,
    log: Any = None,
) -> str:
    """POST lookup for each integration; concatenate successful response bodies.

    Per-integration failures are logged and skipped (playbook WARN behavior).
    """
    body = build_lookup_body(value, polarity_type)
    lookup_headers = {
        **headers,
        'Content-Type': 'application/vnd.api+json',
    }
    parts: list[str] = []
    for integration_id in integration_ids:
        try:
            response = session.post(
                f'/integrations/{integration_id}/lookup',
                headers=lookup_headers,
                json=body,
            )
            if not response.ok:
                if log is not None:
                    log.warning(
                        'Polarity lookup failed integration=%s status=%s reason=%s',
                        integration_id,
                        response.status_code,
                        getattr(response, 'reason', ''),
                    )
                continue
            text = response.text or ''
            if text:
                parts.append(text)
        except Exception as exc:
            if log is not None:
                log.warning(
                    'Polarity lookup error integration=%s error=%s',
                    integration_id,
                    exc,
                )
    return '\n'.join(parts)
