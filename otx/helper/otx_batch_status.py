"""Summarize ThreatConnect v2 batch submit_all status payloads."""

from __future__ import annotations

from typing import Any


def summarize_batch_errors(statuses: Any, *, max_reasons: int = 3) -> str | None:
    """Return a short warning summary of batch errors, or None if none.

    Does not treat item-level errors as hard failure; callers log the result.
    """
    if not isinstance(statuses, list) or not statuses:
        return 'batch returned no status entries'

    total_errors = 0
    total_success = 0
    reasons: list[str] = []

    for entry in statuses:
        if not isinstance(entry, dict) or not entry:
            return 'batch returned empty or invalid status entry'
        error_count = entry.get('errorCount')
        if isinstance(error_count, int):
            total_errors += error_count
        success_count = entry.get('successCount')
        if isinstance(success_count, int):
            total_success += success_count
        errors = entry.get('errors')
        if isinstance(errors, list):
            for item in errors:
                if len(reasons) >= max_reasons:
                    break
                if isinstance(item, dict):
                    reason = item.get('errorReason') or item.get('errorMessage')
                    if reason:
                        reasons.append(str(reason))

    if total_errors <= 0 and not reasons:
        return None

    parts = [f'batch item errors={total_errors} successCount={total_success}']
    if reasons:
        parts.append('samples: ' + ' | '.join(reasons))
    return '; '.join(parts)
