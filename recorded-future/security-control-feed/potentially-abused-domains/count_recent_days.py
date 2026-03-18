"""Count records per day over the last N days from the gzipped domains file.

This script streams the large
`example/Potentially Abused Domains (1).gz` file, which contains a single
top-level JSON object with a large ``results`` array (matching the structure of
``sample_potentially_abused_domains.json``). It uses the ``ijson`` streaming
JSON parser to iterate over each item in the ``results`` array without loading
the entire document into memory.

For each result object, it extracts the ``timestamp`` field and counts how many
records fall on each of the last N calendar days (default 30). Only aggregated
per-day counts are kept in memory and written out to a small text file;
individual records are never stored.

Dependencies
------------
- Requires the ``ijson`` package for streaming JSON parsing:

  pip install ijson

Assumptions
-----------
- The gzipped JSON has a top-level object with a ``results`` array.
- Each result object has a ``timestamp`` field in an ISO-like UTC format such
  as ``YYYY-MM-DDTHH:MM:SS.sssZ`` (e.g., ``2026-02-24T15:18:45.000Z``).
- Timestamps are treated as UTC; we truncate to the UTC date component.

Example usage
-------------
- Default (30 days, default paths):
    python count_recent_days.py

- Verbose output:
    python count_recent_days.py --days 30 --verbose

- Custom paths with overwrite:
    python count_recent_days.py \\
        --input "example/Potentially Abused Domains (1).gz" \\
        --output daily_counts_last_30_days.txt \\
        --force
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import os
import sys
from typing import Dict

import ijson


DEFAULT_INPUT = os.path.join("example", "Potentially Abused Domains (1).gz")
DEFAULT_OUTPUT = "daily_counts_last_30_days.txt"


def _parse_timestamp(value: str) -> dt.date | None:
    """Parse a timestamp string into a UTC date, or return None on failure."""
    if not value:
        return None

    # Handle a common pattern like 2026-02-24T15:18:45.000Z
    # Strip trailing Z if present, then try fromisoformat.
    ts = value.rstrip("Z")
    try:
        return dt.datetime.fromisoformat(ts).date()
    except ValueError:
        # Fallback: try a more explicit format, or give up.
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(ts, fmt).date()
            except ValueError:
                continue
    return None


def count_recent_days(
    input_path: str,
    days: int = 30,
    verbose: bool = False,
) -> Dict[int, int]:
    """Stream the gzipped file and count records per day offset.

    Returns a dict mapping `offset_days` (0 = today, 1 = 1 day ago, ...)
    to counts, for 0 <= offset_days < days.
    """
    if days <= 0:
        raise ValueError("days must be a positive integer.")

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    today = dt.datetime.utcnow().date()
    counts: Dict[int, int] = {offset: 0 for offset in range(days)}

    processed_items = 0
    skipped_parse = 0
    skipped_range = 0

    def _log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    _log(
        f"Reading from '{input_path}', streaming 'results' items for last {days} day(s) "
        f"relative to {today.isoformat()} (UTC)."
    )

    # Open gzipped JSON in binary mode for ijson streaming.
    with gzip.open(input_path, mode="rb") as f_in:
        for record in ijson.items(f_in, "results.item"):
            processed_items += 1

            if not isinstance(record, dict):
                skipped_parse += 1
                continue

            ts_value = record.get("timestamp")
            record_date = _parse_timestamp(ts_value) if isinstance(ts_value, str) else None
            if record_date is None:
                skipped_parse += 1
                continue

            delta = today - record_date
            offset = delta.days
            if 0 <= offset < days:
                counts[offset] += 1
            else:
                skipped_range += 1

    _log(
        f"Finished streaming. Processed_items={processed_items}, "
        f"skipped_parse_or_missing_ts={skipped_parse}, "
        f"skipped_out_of_range={skipped_range}."
    )
    return counts


def write_counts(
    counts: Dict[int, int],
    output_path: str,
    base_date: dt.date | None = None,
    force: bool = False,
) -> None:
    """Write daily counts to a text file in a human-readable format."""
    if base_date is None:
        base_date = dt.datetime.utcnow().date()

    if os.path.exists(output_path) and not force:
        raise FileExistsError(
            f"Output file already exists: {output_path} (use --force to overwrite)"
        )

    with open(output_path, mode="w", encoding="utf-8", newline="") as f_out:
        # Ensure deterministic order from 0 .. N-1.
        for offset in sorted(counts.keys()):
            day = base_date - dt.timedelta(days=offset)
            label = "day" if offset == 1 else "days"
            f_out.write(
                f"{offset} {label} ago ({day.isoformat()}): {counts[offset]} count\n"
            )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count how many records fall on each of the last N days "
            "from a large gzipped JSON file, using the 'timestamp' field."
        )
    )
    parser.add_argument(
        "--input",
        "-i",
        default=DEFAULT_INPUT,
        help=f"Path to input .gz file (default: {DEFAULT_INPUT!r})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Path to output text file (default: {DEFAULT_OUTPUT!r})",
    )
    parser.add_argument(
        "--days",
        "-d",
        type=int,
        default=30,
        help="Number of days back from today (UTC) to count (default: 30).",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Allow overwriting an existing output file.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print progress and summary information to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.days <= 0:
        print("--days must be a positive integer.", file=sys.stderr)
        return 2

    try:
        today = dt.datetime.utcnow().date()
        counts = count_recent_days(
            input_path=args.input,
            days=args.days,
            verbose=args.verbose,
        )
        write_counts(
            counts=counts,
            output_path=args.output,
            base_date=today,
            force=args.force,
        )
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 1
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except gzip.BadGzipFile as e:
        print(f"Failed to read gzip file: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    if args.verbose:
        print(
            f"Successfully wrote daily counts for last {args.days} day(s) "
            f"to {args.output}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

