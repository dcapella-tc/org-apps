"""ThreatConnect Job App"""

from __future__ import annotations

import datetime as dt
import gzip
import re
import os
from typing import Any, Dict, List, Optional
import time

import ijson
from tcex import TcEx
from tcex.exit import ExitCode
from tcex.exit.exit import Exit

from job_app import JobApp  # Import default Job App Class (Required)


EXAMPLE_GZ_PATH = os.path.join("example", "Potentially Abused Domains (1).gz")


def _parse_timestamp_to_datetime(value: str) -> Optional[dt.datetime]:
    """Parse a timestamp string into a UTC datetime, or return None on failure."""
    if not value:
        return None

    ts = value.rstrip("Z")
    try:
        # Handles ISO-like strings with optional fractional seconds
        return dt.datetime.fromisoformat(ts)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(ts, fmt)
            except ValueError:
                continue
    return None


def format_timestamp_iso8601(timestamp_str: str) -> Optional[str]:
    """Normalize a timestamp string to ISO 8601 format with trailing Z.

    Returns None if the input cannot be parsed.
    """
    if not isinstance(timestamp_str, str) or not timestamp_str:
        return None

    parsed = _parse_timestamp_to_datetime(timestamp_str)
    if parsed is None:
        return None

    # Ensure naive datetimes are treated as UTC and append Z
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)

    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_datetime_to_naive_utc(value: dt.datetime) -> dt.datetime:
    """Convert an aware datetime to naive UTC; keep naive datetimes as-is."""
    if value.tzinfo is not None:
        return value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return value


def stream_latest_records(
    input_path: str,
    limit: int = 1000,
    min_timestamp: Optional[dt.datetime] = None,
    max_timestamp: Optional[dt.datetime] = None,
) -> List[Dict[str, Any]]:
    """Stream at most ``limit`` records from the gzipped JSON, ordered by timestamp desc.

    The gzipped file is expected to contain a single top-level JSON object with a large
    ``results`` array, where each item has a ``timestamp`` field. We stream
    ``results.item`` via ijson, stop once we have ``limit`` valid timestamped records,
    then sort them by timestamp in descending order.

    If ``min_timestamp`` is provided, records with ``timestamp <= min_timestamp`` are skipped.
    If ``max_timestamp`` is provided, records with ``timestamp >= max_timestamp`` are skipped.
    """
    if limit <= 0:
        raise ValueError("limit must be a positive integer.")

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    if min_timestamp is not None:
        min_timestamp = _normalize_datetime_to_naive_utc(min_timestamp)
    if max_timestamp is not None:
        max_timestamp = _normalize_datetime_to_naive_utc(max_timestamp)

    collected: List[tuple[dt.datetime, Dict[str, Any]]] = []

    # Binary mode for ijson
    with gzip.open(input_path, mode="rb") as f_in:
        for record in ijson.items(f_in, "results.item"):
            if not isinstance(record, dict):
                continue

            ts_value = record.get("timestamp")
            parsed_ts = (
                _parse_timestamp_to_datetime(ts_value)
                if isinstance(ts_value, str)
                else None
            )
            if parsed_ts is None:
                continue
            parsed_ts = _normalize_datetime_to_naive_utc(parsed_ts)

            # Skip records that are older-or-equal to what we've already processed.
            if min_timestamp is not None and parsed_ts <= min_timestamp:
                continue
            # Skip records that are newer-or-equal to what we've already processed.
            if max_timestamp is not None and parsed_ts >= max_timestamp:
                continue

            collected.append((parsed_ts, record))
            if len(collected) >= limit:
                break

    # Sort newest first
    collected.sort(key=lambda item: item[0], reverse=True)
    return [record for _, record in collected]


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

        # properties
        # self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        # self.tcex.session.external.base_url = 'https://feodotracker.abuse.ch'

    def latest_records(
        self,
        limit: int = 1000,
        since: Optional[dt.datetime] = None,
        until: Optional[dt.datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Return up to ``limit`` records ordered by timestamp descending."""
        try:
            return stream_latest_records(
                EXAMPLE_GZ_PATH,
                limit=limit,
                min_timestamp=since,
                max_timestamp=until,
            )
        except Exception as exc:  # defensive
            self.log.error(f"Failed to stream latest records: {exc}")
            return []

    def batch_run(
        self,
        cutoff: Optional[dt.datetime] = None,
        mode: str = "incremental_new",
    ) -> Optional[dt.datetime]:
        """Run a batch import step and return the next cutoff timestamp.

        Modes:
        - `incremental_new`: fetch records with `timestamp > cutoff` and return the batch max timestamp.
        - `initial_run`: one-time backfill mode that starts from newest records and paginates older.
        """
        if mode not in {"incremental_new", "initial_run"}:
            raise ValueError(f"Unsupported mode: {mode}")

        min_processed_ts: Optional[dt.datetime] = None
        max_processed_ts: Optional[dt.datetime] = None

        def _process_record(record: Dict[str, Any]) -> Optional[dt.datetime]:
            """Create ThreatConnect indicators for one record; return parsed timestamp."""
            summary_domain = record.get("domain")
            summary_apex = record.get("apex_domain")
            raw_timestamp = record.get("timestamp")

            parsed_ts: Optional[dt.datetime] = None
            if isinstance(raw_timestamp, str):
                parsed_ts = _parse_timestamp_to_datetime(raw_timestamp)
                if parsed_ts is not None:
                    parsed_ts = _normalize_datetime_to_naive_utc(parsed_ts)

            last_seen = (
                format_timestamp_iso8601(raw_timestamp)
                if isinstance(raw_timestamp, str)
                else None
            )

            if not summary_domain:
                return parsed_ts

            # Create Host indicator for the full domain (subdomain)
            domain = self.batch.indicator("Host", summary_domain)
            apex = self.batch.indicator("Host", summary_apex)

            # subdomain
            domain.tag("Subdomain")
            domain.tag(f"Apex Domain:{summary_apex}")
            if last_seen:
                domain.attribute("Last Seen", last_seen)
            domain.attribute(
                "Description",
                "The full observed hostname (FQDN) identified in the source data. Represents the specific subdomain associated with the record.",
                True,
            )

            # apex domain
            apex.tag("Apex Domain")
            apex.tag(f"Subdomain:{summary_domain}")
            apex.attribute(
                "Description",
                "The base registrable domain associated with the observed hostname. Represents the parent domain from which the subdomain is derived.",
                True,
            )

            # both indicators
            for indicator in [domain, apex]:
                indicator.tag("Potentially Abused Domain")
                indicator.attribute("Source", "Potentially Abused Domains", True)
                self.batch.save(indicator)

            return parsed_ts

        if mode == "initial_run":
            # batch_pages = int(self.in_.batch_limit)
            # if batch_pages <= 0:
            #     raise ValueError("batch_limit must be a positive integer.")

            # Cursor is the oldest timestamp we've processed so far; next page fetches older (< cursor).
            cutoff_cursor: Optional[dt.datetime] = None
            # for page_index in range(batch_pages):
            # Get up to N relevant records, newest first
            records = self.latest_records(limit=100, since=None, until=cutoff_cursor)
            if not records:
                # if page_index == 0:
                self.log.info(
                    "No records returned from latest_records; skipping initial_run batch import."
                )
                self.tcex.exit(0, "No records to import.")
                # self.log.info(
                #     "No more records returned from latest_records; stopping initial_run pagination."
                # )
                # break

            page_min_processed_ts: Optional[dt.datetime] = None
            for record in records:
                parsed_ts = _process_record(record)
                if parsed_ts is None:
                    continue

                if min_processed_ts is None or parsed_ts < min_processed_ts:
                    min_processed_ts = parsed_ts
                if max_processed_ts is None or parsed_ts > max_processed_ts:
                    max_processed_ts = parsed_ts
                if page_min_processed_ts is None or parsed_ts < page_min_processed_ts:
                    page_min_processed_ts = parsed_ts

            # if page_min_processed_ts is None:
            #     # Avoid looping forever if timestamps are unexpectedly missing.
            #     self.log.info(
            #         "initial_run pagination could not determine a page minimum timestamp; stopping."
            #     )
            #     # break

            # # Next page should be strictly older than what we just processed.
            # cutoff_cursor = page_min_processed_ts
        elif mode == "incremental_new" and cutoff is not None:
            # From given date toward now: paginate with since=cursor, until=None; cursor advances to max_processed_ts.
            # batch_pages = int(self.in_.batch_limit)
            # if batch_pages <= 0:
            #     batch_pages = 100
            cursor: Optional[dt.datetime] = _normalize_datetime_to_naive_utc(cutoff)
            # for page_index in range(batch_pages):
            records = self.latest_records(limit=100, since=cursor, until=None)
            if not records:
                # if page_index == 0:
                self.log.info(
                    "No records returned from latest_records; skipping batch import."
                )
                self.tcex.exit(0, "No records to import.")
                # self.log.info(
                #     "No more records returned; stopping since-date pagination."
                # )
                # break

            for record in records:
                parsed_ts = _process_record(record)
                if parsed_ts is None:
                    continue
                if min_processed_ts is None or parsed_ts < min_processed_ts:
                    min_processed_ts = parsed_ts
                if max_processed_ts is None or parsed_ts > max_processed_ts:
                    max_processed_ts = parsed_ts

            # if max_processed_ts is None:
            #     self.log.info(
            #         "incremental_new pagination could not determine max timestamp; stopping."
            #     )
            #     self.tcex.exit(0, "No records to import.")
            #     # self.log.info(
            #     #     "incremental_new pagination could not determine max timestamp; stopping."
            #     # )
            #     # break
            # cursor = max_processed_ts
        else:
            # Single batch: incremental_new (with or without cutoff).
            since = cutoff if mode == "incremental_new" else None
            until = None

            records = self.latest_records(limit=100, since=since, until=until)
            if not records:
                self.log.info("No records returned from latest_records; skipping batch import.")
                self.tcex.exit(0, "No records to import.")

            for record in records:
                parsed_ts = _process_record(record)
                if parsed_ts is None:
                    continue
                if min_processed_ts is None or parsed_ts < min_processed_ts:
                    min_processed_ts = parsed_ts
                if max_processed_ts is None or parsed_ts > max_processed_ts:
                    max_processed_ts = parsed_ts

        batch_response = self.batch.submit_all()
        self.batch.close()

        errors = []
        successes = []
        for item in batch_response:
            errors.extend(item.get('errors', []))
            successes.extend(item.get('successes', []))
        if errors:
            known_errors = []
            self.tcex.log.error('App.run: batch submission failed with %d errors', len(errors))

            error_count = 0
            for error in errors:
                error_count += 1
                if error_count == 100: break
                error_reason = error.get('errorReason', '').split('is not valid. ')[1]
                known_error = re.sub(r"'[^']*'", '', error_reason).strip()
                if known_error in known_errors:
                    continue
                known_errors.append(known_error)
                self.tcex.log.error('App.run: batch submission error: %s', error)
                
                

        if successes:
            self.tcex.log.info('App.run: batch submission successful with %d items', len(successes))
            self.tcex.log.info('App.run: batch submission success: %s', successes[0])

        if mode == "incremental_new":
            return max_processed_ts
        return min_processed_ts

    def run(self):
        """Run main App logic."""
        max_runs = self.in_.batch_limit
        if max_runs <= 0:
            max_runs = 1

        cutoff: Optional[dt.datetime] = None
        mode = "initial_run"
        if self.in_.initial_run:
            mode = "initial_run"
        else:
            # Non-initial run: if since_date is set, fetch from that date toward now.
            since_date_str = str(getattr(self.in_, "since_date", "") or "").strip()
            if since_date_str:
                parsed_since = _parse_timestamp_to_datetime(since_date_str)
                if parsed_since is not None:
                    cutoff = _normalize_datetime_to_naive_utc(parsed_since)
                    mode = "incremental_new"
                else:
                    self.log.warning(
                        "since_date could not be parsed; since_date required for non-initial run."
                    )
                    self.tcex.exit(0, "since_date required for non-initial run; no records imported.")
            else:
                self.log.info("since_date not set; required for non-initial run.")
                self.tcex.exit(0, "since_date required for non-initial run; no records imported.")

        for i in range(max_runs):
            try:
                self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
                cutoff = self.batch_run(cutoff=cutoff, mode=mode)
            except Exception as exc:
                if "Could not retrieve indicator types from ThreatConnect API." in str(exc):
                    self.tcex.exit.exit(ExitCode.FAILURE, 'Could not retrieve indicator types from ThreatConnect API.')
                self.tcex.log.error(f"Failed to run batch: {exc}")
                time.sleep(1)



