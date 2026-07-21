"""Tests for helper.otx_save and helper.otx_flatten."""

import csv
import json
from pathlib import Path

from helper.otx_flatten import flatten_pulse, flatten_pulses
from helper.otx_save import (
    RAW_JSON_FILENAME,
    SHEET_CSV_FILENAME,
    save_inspection_files,
)


def test_flatten_pulse():
    pulse = {
        'id': 'abc',
        'name': 'Example',
        'author_name': 'alice',
        'created': '2026-01-01T00:00:00',
        'modified': '2026-01-02T00:00:00',
        'tags': ['malware', 'c2'],
        'indicators': [{'type': 'IPv4'}, {'type': 'domain'}],
        'tlp': 'white',
        'references': ['https://a.example', 'https://b.example'],
    }
    row = flatten_pulse(pulse)
    assert row['id'] == 'abc'
    assert row['tags'] == 'malware|c2'
    assert row['indicator_count'] == '2'
    assert row['references'] == 'https://a.example|https://b.example'


def test_flatten_pulses_empty():
    assert flatten_pulses([]) == []


def test_save_inspection_files(tmp_path: Path):
    payload = {
        'count': 1,
        'results': [
            {
                'id': '1',
                'name': 'Pulse One',
                'author_name': 'bob',
                'created': '2026-01-01T00:00:00',
                'modified': '2026-01-02T00:00:00',
                'tags': ['tag1'],
                'indicator_count': 3,
                'tlp': 'green',
                'references': [],
            }
        ],
        'pages': 1,
    }
    json_path, csv_path = save_inspection_files(payload, tmp_path)

    assert json_path == tmp_path / RAW_JSON_FILENAME
    assert csv_path == tmp_path / SHEET_CSV_FILENAME
    assert json_path.is_file()
    assert csv_path.is_file()

    loaded = json.loads(json_path.read_text(encoding='utf-8'))
    assert loaded['count'] == 1
    assert loaded['results'][0]['id'] == '1'

    with csv_path.open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]['name'] == 'Pulse One'
    assert rows[0]['tags'] == 'tag1'
