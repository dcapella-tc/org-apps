"""Retry wrapper for OTX HTTP calls that frequently timeout."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

# Retryable HTTP status codes from OTX (known 504 issues on /pulses/subscribed).
RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})

DEFAULT_MAX_ATTEMPTS = 5
# Backoff delays between attempts (seconds); length = max_attempts - 1.
DEFAULT_BACKOFF_SECONDS = (2, 4, 8, 16)
# Per-attempt request timeouts (seconds); padded with last value if needed.
DEFAULT_TIMEOUTS = (60, 90, 120, 120, 120)


class RetryableHttpError(Exception):
    """Raised when an HTTP response status should be retried."""

    def __init__(self, status_code: int, message: str = ''):
        self.status_code = status_code
        super().__init__(message or f'HTTP {status_code}')


def is_retryable_status(status_code: int) -> bool:
    """Return True if the HTTP status code warrants a retry."""
    return status_code in RETRYABLE_STATUS_CODES


def timeout_for_attempt(attempt: int, timeouts: tuple[int, ...] = DEFAULT_TIMEOUTS) -> int:
    """Return the timeout (seconds) for a 1-based attempt number."""
    index = max(0, attempt - 1)
    if index < len(timeouts):
        return timeouts[index]
    return timeouts[-1]


def backoff_for_attempt(
    attempt: int,
    backoff_seconds: tuple[int, ...] = DEFAULT_BACKOFF_SECONDS,
) -> int:
    """Return sleep seconds after a failed 1-based attempt (before next try)."""
    index = max(0, attempt - 1)
    if index < len(backoff_seconds):
        return backoff_seconds[index]
    return backoff_seconds[-1]


def call_with_retries(
    operation: Callable[[int], Any],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    timeouts: tuple[int, ...] = DEFAULT_TIMEOUTS,
    backoff_seconds: tuple[int, ...] = DEFAULT_BACKOFF_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    log_fn: Callable[[str], None] | None = None,
) -> Any:
    """Invoke ``operation(timeout)`` with retries on timeout / connection / retryable HTTP.

    ``operation`` receives the per-attempt timeout in seconds and should raise
    ``RetryableHttpError`` for retryable HTTP statuses, or standard timeout /
    connection exceptions for network failures. Non-retryable exceptions propagate.
    """
    last_error: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        timeout = timeout_for_attempt(attempt, timeouts)
        try:
            return operation(timeout)
        except RetryableHttpError as exc:
            last_error = exc
            if log_fn:
                log_fn(
                    f'otx-retry attempt={attempt}/{max_attempts} '
                    f'status={exc.status_code} timeout={timeout}'
                )
        except (TimeoutError, ConnectionError, OSError) as exc:
            last_error = exc
            if log_fn:
                log_fn(
                    f'otx-retry attempt={attempt}/{max_attempts} '
                    f'error={type(exc).__name__}: {exc} timeout={timeout}'
                )
        except Exception as exc:
            # requests-style exceptions (ReadTimeout, ConnectionError subclasses, etc.)
            name = type(exc).__name__.lower()
            retryable_names = (
                'timeout',
                'readtimeout',
                'connecttimeout',
                'connectionerror',
                'chunkedencodingerror',
            )
            if not any(token in name for token in retryable_names):
                raise
            last_error = exc
            if log_fn:
                log_fn(
                    f'otx-retry attempt={attempt}/{max_attempts} '
                    f'error={type(exc).__name__}: {exc} timeout={timeout}'
                )

        if attempt < max_attempts:
            delay = backoff_for_attempt(attempt, backoff_seconds)
            if log_fn:
                log_fn(f'otx-retry sleeping={delay}s before next attempt')
            sleep_fn(delay)

    raise last_error if last_error is not None else RuntimeError('retry exhausted with no error')
