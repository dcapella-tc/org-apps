"""Flatten OTX pulse objects into CSV row dicts for inspection."""

from __future__ import annotations

from typing import Any

CSV_COLUMNS = (
    'id',
    'name',
    'author_name',
    'created',
    'modified',
    'tags',
    'indicator_count',
    'tlp',
    'references',
)


def _join_list(value: Any, delimiter: str = '|') -> str:
    if not isinstance(value, list):
        return '' if value is None else str(value)
    return delimiter.join(str(item) for item in value)


def flatten_pulse(pulse: dict[str, Any]) -> dict[str, str]:
    """Flatten one pulse object into a CSV-ready string dict."""
    indicators = pulse.get('indicators')
    if isinstance(indicators, list):
        indicator_count = str(len(indicators))
    elif pulse.get('indicator_count') is not None:
        indicator_count = str(pulse.get('indicator_count'))
    else:
        indicator_count = ''

    return {
        'id': '' if pulse.get('id') is None else str(pulse.get('id')),
        'name': '' if pulse.get('name') is None else str(pulse.get('name')),
        'author_name': (
            '' if pulse.get('author_name') is None else str(pulse.get('author_name'))
        ),
        'created': '' if pulse.get('created') is None else str(pulse.get('created')),
        'modified': '' if pulse.get('modified') is None else str(pulse.get('modified')),
        'tags': _join_list(pulse.get('tags')),
        'indicator_count': indicator_count,
        'tlp': '' if pulse.get('tlp') is None else str(pulse.get('tlp')),
        'references': _join_list(pulse.get('references')),
    }


def flatten_pulses(pulses: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Flatten a list of pulse objects into CSV row dicts."""
    return [flatten_pulse(pulse) for pulse in pulses]
