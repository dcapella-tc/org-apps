"""Build ThreatConnect tag names from an OTX pulse."""

from __future__ import annotations

from typing import Any

from helper.otx_target_country import resolve_targeted_countries

MAX_TAG_LENGTH = 128


def build_pulse_tags(pulse: dict[str, Any]) -> list[str]:
    """Return deduplicated tag names for a pulse (order preserved).

    ``Target Country:`` tags are only added for countries that do not map to
    the ThreatConnect Target Country attribute allowlist.
    """
    tags: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        text = str(name).strip()
        if not text:
            return
        if len(text) > MAX_TAG_LENGTH:
            text = text[:MAX_TAG_LENGTH]
        key = text.casefold()
        if key in seen:
            return
        seen.add(key)
        tags.append(text)

    for value in pulse.get('tags') or []:
        add(str(value))

    for value in pulse.get('attack_ids') or []:
        add(str(value))

    for value in pulse.get('industries') or []:
        add(str(value))

    revision = pulse.get('revision')
    if revision is not None and str(revision).strip():
        add(f'revision:{str(revision).strip()}')

    _mapped, unmatched = resolve_targeted_countries(pulse)
    for country_text in unmatched:
        add(f'Target Country:{country_text}')

    return tags
