"""Map ThreatConnect indicator types to Polarity entity types."""

from __future__ import annotations

from typing import Any


def map_polarity_type(indicator: dict[str, Any]) -> str | None:
    """Return the Polarity entity type for a TC indicator, or None if unsupported.

    Mapping mirrors the playbook JMES expression:
    Host → domain, Address → IPv4/IPv6, File → SHA256/SHA1/MD5,
    Email Subject/EmailAddress → email, URL → url.
    """
    tc_type = indicator.get('type') or ''

    if tc_type == 'Host':
        return 'domain'

    if tc_type == 'Address':
        ip = str(indicator.get('ip') or indicator.get('summary') or '')
        return 'IPv6' if ':' in ip else 'IPv4'

    if tc_type == 'File':
        if indicator.get('sha256'):
            return 'SHA256'
        if indicator.get('sha1'):
            return 'SHA1'
        if indicator.get('md5'):
            return 'MD5'
        return None

    if tc_type in ('Email Subject', 'EmailAddress'):
        return 'email'

    if tc_type == 'URL':
        return 'url'

    return None
