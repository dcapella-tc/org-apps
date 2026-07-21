"""Tests for helper.otx.Otx orchestration."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from helper.otx import Otx
from tests.helpers import make_tcex


def _json_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.ok = True
    response.json.return_value = payload
    response.content = b''
    return response


def test_fetch_subscribed_pulses_paginates():
    http_session = MagicMock()
    http_session.get.side_effect = [
        _json_response(
            {
                'count': 2,
                'results': [{'id': '1', 'name': 'a'}],
                'next': 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=2',
            }
        ),
        _json_response(
            {
                'count': 2,
                'results': [{'id': '2', 'name': 'b'}],
                'next': None,
            }
        ),
    ]
    tcex = make_tcex(http_session)
    otx = Otx(tcex, api_key='test-key')

    payload = otx.fetch_subscribed_pulses(datetime(2026, 7, 18, tzinfo=UTC))

    assert payload['pages'] == 2
    assert [p['id'] for p in payload['results']] == ['1', '2']
    assert http_session.get.call_count == 2


def test_fetch_with_widening_window_widens_on_empty(tmp_path: Path):
    empty = _json_response({'count': 0, 'results': [], 'next': None})
    filled = _json_response(
        {
            'count': 1,
            'results': [{'id': 'x', 'name': 'found', 'tags': []}],
            'next': None,
        }
    )
    http_session = MagicMock()
    http_session.get.side_effect = [empty, filled]
    tcex = make_tcex(http_session)
    otx = Otx(tcex, api_key='test-key')

    # Start at the default 24h window so widen can move to 48h.
    start = datetime.now(tz=UTC) - timedelta(hours=24)
    payload = otx.fetch_with_widening_window(start, out_dir=tmp_path)

    assert len(payload['results']) == 1
    assert payload['results'][0]['id'] == 'x'
    assert (tmp_path / 'otx_pulses_raw.json').is_file()
    assert (tmp_path / 'otx_pulses_sheet.csv').is_file()
    assert http_session.get.call_count == 2


def test_save_inspection_files_delegates(tmp_path: Path):
    tcex = make_tcex()
    otx = Otx(tcex, api_key='k')
    payload = {'count': 0, 'results': [], 'pages': 0}
    json_path, csv_path = otx.save_inspection_files(payload, tmp_path)
    assert json_path.exists()
    assert csv_path.exists()
