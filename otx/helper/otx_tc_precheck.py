"""Precheck ThreatConnect batch write access for an owner."""

from __future__ import annotations

from typing import Protocol


class _Session(Protocol):
    def post(self, url: str, *, json: dict | None = None): ...


def batch_create_settings(owner: str) -> dict[str, str]:
    """Return V2 batch Create settings matching TcEx BatchSubmit defaults."""
    return {
        'action': 'Create',
        'attributeWriteType': 'Replace',
        'haltOnError': 'true',
        'owner': owner,
        'playbookTriggersEnabled': 'false',
        'securityLabelWriteType': 'Replace',
        'tagWriteType': 'Replace',
        'version': 'V2',
    }


def assert_owner_batch_writable(session_tc: _Session, owner: str) -> None:
    """Verify the Job identity can create a V2 batch job in ``owner``.

    Posts ``POST /v2/batch`` without uploading content. Raises ``PermissionError``
    when the API rejects create (e.g. HTTP 401 permission message).
    """
    owner_name = str(owner or '').strip()
    if not owner_name:
        raise PermissionError('ThreatConnect Owner (tc_owner) is empty.')

    response = session_tc.post('/v2/batch', json=batch_create_settings(owner_name))
    status = getattr(response, 'status_code', None)
    text = getattr(response, 'text', '') or ''
    ok = bool(getattr(response, 'ok', False))

    if ok:
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if isinstance(payload, dict) and payload.get('status') == 'Success':
            return
        raise PermissionError(
            f'Cannot create batch job in owner "{owner_name}": '
            f'unexpected API status. HTTP {status}: {text[:500]}'
        )

    raise PermissionError(
        f'Cannot create batch job in owner "{owner_name}" '
        f'(HTTP {status}). Ensure the Job identity has create permission '
        f'for Indicators, Groups, Attributes, Tags, and Security Labels. '
        f'API message: {text[:500]}'
    )
