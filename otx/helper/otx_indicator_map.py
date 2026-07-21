"""Map one OTX indicator dict to a ThreatConnect batch factory call."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

BatchMethod = Literal['address', 'host', 'url', 'email_address', 'file']


@dataclass(frozen=True)
class MappedIndicator:
    """Instructions for creating one TC batch indicator from an OTX indicator."""

    method: BatchMethod
    # Positional/keyword args passed to batch.<method>(...)
    kwargs: dict[str, Any]
    # Raw OTX indicator id (for xid) and optional metadata.
    otx_id: str | None
    description: str | None
    created: str | None


def map_otx_indicator(indicator: dict[str, Any] | None) -> MappedIndicator | None:
    """Map an OTX indicator object to batch factory args, or None if unsupported."""
    if not isinstance(indicator, dict):
        return None

    otx_type = str(indicator.get('type') or '').strip()
    value = indicator.get('indicator')
    if value is None or str(value).strip() == '':
        return None
    value_str = str(value).strip()

    otx_id = indicator.get('id')
    otx_id_str = None if otx_id is None else str(otx_id)

    description = _first_nonempty(indicator.get('description'), indicator.get('title'))
    created = indicator.get('created')
    created_str = None if created is None else str(created)

    method: BatchMethod | None = None
    kwargs: dict[str, Any] = {}

    if otx_type in ('IPv4', 'IPv6'):
        method = 'address'
        kwargs = {'ip': value_str}
    elif otx_type in ('hostname', 'domain'):
        method = 'host'
        kwargs = {'hostname': value_str}
    elif otx_type == 'URL':
        method = 'url'
        kwargs = {'text': value_str}
    elif otx_type.lower() == 'email':
        method = 'email_address'
        kwargs = {'address': value_str}
    elif otx_type == 'FileHash-MD5':
        method = 'file'
        kwargs = {'md5': value_str}
    elif otx_type == 'FileHash-SHA1':
        method = 'file'
        kwargs = {'sha1': value_str}
    elif otx_type == 'FileHash-SHA256':
        method = 'file'
        kwargs = {'sha256': value_str}
    else:
        return None

    return MappedIndicator(
        method=method,
        kwargs=kwargs,
        otx_id=otx_id_str,
        description=description,
        created=created_str,
    )


def _first_nonempty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None
