"""Execute a single OTX GET via tcex.session.external (no parsing, no retries)."""

from __future__ import annotations

from typing import Any

from tcex import TcEx
from tcex.exit import ExitCode

from helper.otx_retry import RetryableHttpError, is_retryable_status

HTTP_ERROR_BODY_LOG_MAX = 500


def fetch_page(
    tcex: TcEx,
    *,
    path: str,
    headers: dict[str, str],
    timeout: int,
) -> Any:
    """Perform one GET and return the Response object.

    Raises:
        RetryableHttpError: For 502/503/504 so callers can retry.
        Does not return on non-retryable HTTP failures; calls ``tcex.exit.exit``.
    """
    try:
        with tcex.session.external as session:
            response = session.get(path, headers=headers, timeout=timeout)
    except Exception:
        # Let retry wrapper handle timeout/connection; re-raise as-is.
        raise

    if response.ok:
        return response

    status = response.status_code
    if is_retryable_status(status):
        raise RetryableHttpError(status, f'OTX returned HTTP {status}')

    tcex.log.error('OTX request failed with status %s path=%s', status, path)
    body_preview = ''
    try:
        body_preview = (response.text or '')[:HTTP_ERROR_BODY_LOG_MAX]
    except Exception:
        pass
    if body_preview:
        tcex.log.error('OTX response body (truncated): %s', body_preview)

    tcex.exit.exit(
        ExitCode.FAILURE,
        f'OTX request failed with status {status}',
    )
