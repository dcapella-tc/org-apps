"""Evaluate ThreatConnect v2 batch submit_all status payloads."""

from __future__ import annotations

from typing import Any


def batch_submit_succeeded(statuses: Any, *, had_work: bool) -> bool:
    """Return True only when every status is a non-empty success (or no work).

    When ``had_work`` is False (nothing queued), an empty status list is success.
    When ``had_work`` is True, empty statuses, empty dicts (e.g. HTTP 401 path),
    error counts, or ``successCount == 0`` are failures.
    """
    if not had_work:
        return True

    if not isinstance(statuses, list) or not statuses:
        return False

    for entry in statuses:
        if not isinstance(entry, dict) or not entry:
            return False
        error_count = entry.get('errorCount')
        if isinstance(error_count, int) and error_count > 0:
            return False
        errors = entry.get('errors')
        if isinstance(errors, list) and errors:
            return False
        if 'successCount' in entry and entry.get('successCount') == 0:
            return False

    return True
