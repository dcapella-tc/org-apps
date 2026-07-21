"""Normalize OTX field names to ThreatConnect attribute type names."""

from __future__ import annotations

# Explicit overrides for known OTX fields (plan mapping).
ATTRIBUTE_NAME_OVERRIDES: dict[str, str] = {
    'description': 'Description',
    'author_name': 'Author',
    'created': 'External Date Created',
    'modified': 'External Date Last Modified',
    'id': 'External ID',
    'public': 'Availability to Public',
    'references': 'External References',
    'extract_source': 'Source',
    'targeted_countries': 'Target Country',
}


def normalize_attr_name(field_name: str) -> str:
    """Convert an OTX field name to a TC attribute type string.

    Uses known overrides when present; otherwise Title-Cases snake_case
    (e.g. ``targeted_countries`` → ``Target Country`` via override).
    """
    key = (field_name or '').strip()
    if not key:
        return ''
    if key in ATTRIBUTE_NAME_OVERRIDES:
        return ATTRIBUTE_NAME_OVERRIDES[key]
    parts = key.replace('-', '_').split('_')
    return ' '.join(part.capitalize() for part in parts if part)
