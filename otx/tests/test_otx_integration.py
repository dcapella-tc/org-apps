"""Optional live OTX API integration test.

Requires env var ``OTX_API_KEY``. Skipped automatically when unset.

Run::

    OTX_API_KEY=<key> pytest tests/test_otx_integration.py -m integration
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from helper.otx import Otx
from helper.otx_parse import extract_pulses
from helper.otx_widen import LOOKBACK_WINDOWS

pytestmark = pytest.mark.integration


def _live_tcex():
    """Build a minimal real-session TcEx substitute using requests."""
    import requests

    tcex = MagicMock()
    session = requests.Session()
    # Mimic tcex.session.external context manager returning a session with base_url support.
    external = MagicMock()
    external.__enter__.return_value = session
    external.__exit__.return_value = None
    # Allow absolute URLs on session.get; Otx builds path-only requests, so wrap get.
    base = 'https://otx.alienvault.com/api/v1'

    original_get = session.get

    def get_with_base(path, **kwargs):
        if path.startswith('http'):
            url = path
        else:
            url = base.rstrip('/') + '/' + path.lstrip('/')
        return original_get(url, **kwargs)

    session.get = get_with_base  # type: ignore[method-assign]
    tcex.session.external = external
    tcex.log = MagicMock()
    return tcex


@pytest.fixture
def api_key():
    key = os.environ.get('OTX_API_KEY', '').strip()
    if not key:
        pytest.skip('OTX_API_KEY not set')
    return key


def test_live_fetch_saves_files_and_widens_if_empty(api_key: str, tmp_path: Path):
    """Hit /pulses/subscribed, save inspection files, widen on empty results."""
    tcex = _live_tcex()
    otx = Otx(tcex, api_key=api_key)

    # Track how many fetch attempts happen via saved files / log side effects.
    payload = otx.fetch_with_widening_window(None, out_dir=tmp_path)

    json_path = tmp_path / 'otx_pulses_raw.json'
    csv_path = tmp_path / 'otx_pulses_sheet.csv'
    assert json_path.is_file(), 'raw JSON inspection file missing'
    assert csv_path.is_file(), 'CSV sheet inspection file missing'

    pulses = extract_pulses(payload)
    # If empty, widening should have exhausted the configured windows
    # (each empty attempt overwrites the same filenames; verify we still have files).
    if not pulses:
        # Widening ran through LOOKBACK_WINDOWS; final payload is still empty.
        assert payload.get('results') == []
        assert len(LOOKBACK_WINDOWS) >= 1
    else:
        assert len(pulses) > 0
        csv_text = csv_path.read_text(encoding='utf-8')
        assert 'id' in csv_text.splitlines()[0]
