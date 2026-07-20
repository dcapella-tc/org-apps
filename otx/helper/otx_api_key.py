"""Resolve OTX API key from app input or environment (.env via tcex run)."""

from __future__ import annotations

import os

PLACEHOLDER_VALUES = frozenset(
    {
        '',
        'REPLACE_WITH_OTX_API_KEY',
    }
)


def _normalize(value: str | None) -> str | None:
    """Return stripped value, or None if unset / placeholder."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in PLACEHOLDER_VALUES:
        return None
    return text


def resolve_otx_api_key(input_value: str | None = None) -> str:
    """Resolve OTX API key from app input, then ``otx_api_key`` / ``OTX_API_KEY`` env.

    Empty strings and the local-dev placeholder ``REPLACE_WITH_OTX_API_KEY`` are
    treated as unset so ``.env`` (loaded by ``tcex run`` via ``load_dotenv``) can
    supply the key the same way standard TC credentials do.

    Raises:
        ValueError: When neither input nor environment provides a key.
    """
    from_input = _normalize(input_value)
    if from_input is not None:
        return from_input

    from_env = _normalize(os.getenv('otx_api_key')) or _normalize(os.getenv('OTX_API_KEY'))
    if from_env is not None:
        return from_env

    raise ValueError(
        'OTX API key not found. Set otx_api_key in .env (local tcex run) '
        'or provide the otx_api_key app input (ThreatConnect / KeyVault).'
    )
