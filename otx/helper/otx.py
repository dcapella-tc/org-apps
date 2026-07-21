"""Thin Otx client that composes single-purpose helper modules."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from tcex import TcEx
from tcex.exit import ExitCode

from helper.otx_dates import resolve_last_modified
from helper.otx_fetch import fetch_page
from helper.otx_parse import extract_pulses, has_next_page, merge_page_payloads, parse_response_json
from helper.otx_request import DEFAULT_PAGE_LIMIT, build_auth_headers, build_subscribed_path
from helper.otx_retry import call_with_retries
from helper.otx_save import save_inspection_files
from helper.otx_widen import next_wider_last_modified

DEFAULT_BASE_URL = 'https://otx.alienvault.com/api/v1/'


class Otx:
    """Fetch subscribed OTX pulses, widen empty windows, and save inspection files."""

    def __init__(
        self,
        tcex: TcEx,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        page_limit: int = DEFAULT_PAGE_LIMIT,
    ):
        """Initialize with TcEx context and OTX API key."""
        self.tcex = tcex
        self.api_key = api_key
        self.base_url = base_url.rstrip('/') + '/'
        self.page_limit = page_limit
        self.log = tcex.log

    def fetch_subscribed_pulses(self, last_modified: datetime | None = None) -> dict[str, Any]:
        """Fetch all pages of subscribed pulses; return a combined payload."""
        window_start = resolve_last_modified(last_modified)
        headers = build_auth_headers(self.api_key)
        pages: list[dict[str, Any]] = []
        page = 1

        while True:
            path = build_subscribed_path(
                window_start,
                page=page,
                limit=self.page_limit,
            )
            self.log.info(
                'otx-fetch page=%s path=%s modified_since=%s',
                page,
                path,
                window_start.isoformat(),
            )
            response = self._fetch_page_with_retries(path=path, headers=headers)
            payload = parse_response_json(response)
            pages.append(payload)

            if not has_next_page(payload):
                break
            page += 1

        return merge_page_payloads(pages)

    def save_inspection_files(
        self,
        payload: dict[str, Any],
        out_dir: Path,
    ) -> tuple[Path, Path]:
        """Save raw JSON and flattened CSV; return both paths."""
        return save_inspection_files(payload, out_dir)

    def fetch_with_widening_window(
        self,
        last_modified: datetime | None = None,
        *,
        out_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Fetch pulses; if empty, re-run with progressively wider lookbacks.

        When ``out_dir`` is set, each attempt's payload is saved for inspection
        before deciding whether to widen.
        """
        window_start = resolve_last_modified(last_modified)
        payload: dict[str, Any] = {'count': 0, 'results': [], 'pages': 0}

        while True:
            self.log.info(
                'otx-window attempt modified_since=%s',
                window_start.isoformat(),
            )
            payload = self.fetch_subscribed_pulses(window_start)
            pulses = extract_pulses(payload)
            pulse_count = len(pulses)
            self.log.info(
                'otx-window result modified_since=%s pulse_count=%s',
                window_start.isoformat(),
                pulse_count,
            )

            if out_dir is not None:
                json_path, csv_path = self.save_inspection_files(payload, out_dir)
                self.log.info(
                    'otx-window saved json=%s csv=%s',
                    json_path,
                    csv_path,
                )

            if pulse_count > 0:
                return payload

            wider = next_wider_last_modified(window_start)
            if wider is None:
                self.log.warning(
                    'otx-window exhausted lookbacks with zero pulses '
                    'last_modified=%s',
                    window_start.isoformat(),
                )
                return payload

            self.log.info(
                'otx-window widening from=%s to=%s',
                window_start.isoformat(),
                wider.isoformat(),
            )
            window_start = wider

    def _fetch_page_with_retries(self, *, path: str, headers: dict[str, str]) -> Any:
        """Fetch one page with timeout/backoff retries."""

        def operation(timeout: int) -> Any:
            return fetch_page(
                self.tcex,
                path=path,
                headers=headers,
                timeout=timeout,
            )

        def log_fn(message: str) -> None:
            self.log.warning(message)

        try:
            return call_with_retries(operation, log_fn=log_fn)
        except Exception as exc:
            self.log.exception('OTX fetch failed after retries path=%s', path)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'OTX fetch failed after retries: {exc}',
            )
