"""Write OTX inspection JSON and CSV files to disk."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from helper.otx_flatten import CSV_COLUMNS, flatten_pulses
from helper.otx_parse import extract_pulses

RAW_JSON_FILENAME = 'otx_pulses_raw.json'
SHEET_CSV_FILENAME = 'otx_pulses_sheet.csv'


def save_raw_json(payload: dict[str, Any], out_dir: Path) -> Path:
    """Write the raw combined payload as JSON; return the file path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RAW_JSON_FILENAME
    path.write_text(json.dumps(payload, indent=2, default=str), encoding='utf-8')
    return path


def save_sheet_csv(payload: dict[str, Any], out_dir: Path) -> Path:
    """Write flattened pulses as a CSV sheet; return the file path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / SHEET_CSV_FILENAME
    rows = flatten_pulses(extract_pulses(payload))

    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)

    return path


def save_inspection_files(payload: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    """Save raw JSON and flattened CSV; return ``(json_path, csv_path)``."""
    json_path = save_raw_json(payload, out_dir)
    csv_path = save_sheet_csv(payload, out_dir)
    return json_path, csv_path
