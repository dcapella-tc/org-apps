"""Build ThreatConnect attribute tuples from an OTX pulse."""

from __future__ import annotations

from typing import Any

from helper.otx_attr_names import normalize_attr_name
from helper.otx_target_country import resolve_targeted_countries

# (attr_type, value, displayed)
AttributeTuple = tuple[str, str, bool]

# Scalar / list fields imported as attributes (not tags-only, not separate objects).
# created/modified are Report metadata (publish_date / external_*); not attributes.
_SCALAR_FIELDS = (
    'description',
    'author_name',
    'id',
    'public',
)

_LIST_AS_ONE_PER_ITEM = (
    ('references', True),
    ('extract_source', False),
)


def build_pulse_attributes(pulse: dict[str, Any]) -> list[AttributeTuple]:
    """Return attribute tuples ``(type, value, displayed)`` for a pulse."""
    attrs: list[AttributeTuple] = []

    for field in _SCALAR_FIELDS:
        raw = pulse.get(field)
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        attr_type = normalize_attr_name(field)
        displayed = field == 'description'
        attrs.append((attr_type, text, displayed))

    for field, displayed in _LIST_AS_ONE_PER_ITEM:
        values = pulse.get(field) or []
        if not isinstance(values, list):
            continue
        attr_type = normalize_attr_name(field)
        for item in values:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                attrs.append((attr_type, text, displayed))

    mapped_countries, _unmatched = resolve_targeted_countries(pulse)
    for country in mapped_countries:
        attrs.append(('Target Country', country, False))

    return attrs


def tlp_security_label(tlp: Any) -> str | None:
    """Map OTX TLP string to a TC security label name, or None."""
    if tlp is None:
        return None
    normalized = str(tlp).strip().lower()
    mapping = {
        'white': 'TLP:WHITE',
        'green': 'TLP:GREEN',
        'amber': 'TLP:AMBER',
        'red': 'TLP:RED',
        'clear': 'TLP:CLEAR',
    }
    return mapping.get(normalized)
