"""ThreatConnect Job App"""

from __future__ import annotations

import datetime as dt
import gzip
import os
from typing import Any, Dict, List, Optional

import ijson
from tcex import TcEx
from tcex.exit import ExitCode

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


def stream_latest_records(input_path: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """Stream at most ``limit`` records from the gzipped JSON, ordered by timestamp desc.

    The gzipped file is expected to contain a single top-level JSON object with a large
    ``results`` array, where each item has a ``timestamp`` field. We stream
    ``results.item`` via ijson, stop once we have ``limit`` valid timestamped records,
    then sort them by timestamp in descending order.
    """
    if limit <= 0:
        raise ValueError("limit must be a positive integer.")

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

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
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        # self.tcex.session.external.base_url = 'https://feodotracker.abuse.ch'

    def latest_records(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return up to ``limit`` records ordered by timestamp descending."""
        try:
            return stream_latest_records(EXAMPLE_GZ_PATH, limit=limit)
        except Exception as exc:  # defensive
            self.log.error(f"Failed to stream latest records: {exc}")
            return []

    def run(self):
        """Run main App logic."""
        # Get the 1,000 most recent records, newest first
        records = self.latest_records(limit=1000)

        if not records:
            self.log.info("No records returned from latest_records; skipping batch import.")
            self.tcex.exit(0, "No records to import.")

        for record in records:
            summary_domain = record.get("domain")
            summary_apex = record.get("apex_domain")
            raw_timestamp = record.get("timestamp")
            last_seen = (
                format_timestamp_iso8601(raw_timestamp)
                if isinstance(raw_timestamp, str)
                else None
            )

            if not summary_domain:
                continue

            # Create Host indicator for the full domain (subdomain)
            domain = self.batch.indicator('Host', summary_domain)
            apex = self.batch.indicator('Host', summary_apex)

            # subdomain
            domain.tag('Subdomain')
            domain.tag(f'Apex Domain:{summary_apex}')
            if last_seen:
                domain.attribute('Last Seen', last_seen)
            domain.attribute('Description', 'The full observed hostname (FQDN) identified in the source data. Represents the specific subdomain associated with the record.', True)
            
            # apex domain
            apex.tag('Apex Domain')
            apex.tag(f'Subdomain:{summary_domain}')
            apex.attribute('Description', 'The base registrable domain associated with the observed hostname. Represents the parent domain from which the subdomain is derived.', True)

            # both indicators
            for indicator in [domain, apex]:
                indicator.tag('Potentially Abused Domain')
                indicator.attribute('Source', 'Potentially Abused Domains', True)
                self.batch.save(indicator)

        batch_response = self.batch.submit_all()
        self.batch.close()

        errors = []
        successes = []
        for item in batch_response:
            errors.extend(item.get('errors', []))
            successes.extend(item.get('successes', []))
        if errors:
            self.tcex.log.error('App.run: batch submission failed with %d errors', len(errors))
            for i,error in enumerate(errors):
                if i == 10: break
                self.tcex.log.error('App.run: batch submission error: %s', error)
            # self.tcex.log.debug('App.run: batch submission errors: %s', json.dumps(errors, indent=4))

        if successes:
            self.tcex.log.info('App.run: batch submission successful with %d items', len(successes))
            self.tcex.log.info('App.run: batch submission success: %s', successes[0])


