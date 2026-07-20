"""ThreatConnect Exchange Job App."""

import csv
from io import StringIO
from pathlib import Path
from typing import Any

from job_app import JobApp

OUTPUT_CSV = 'data.csv'


def query_indicators_by_tql_stub(tql: str) -> dict[str, Any]:
    """Return a fixed v3-style indicators payload (theoretical API call).

    Replace with a real ThreatConnect v3 indicators request using ``tql`` when ready.

    Args:
        tql: Indicator TQL from Job inputs (unused by the stub).

    Returns:
        Dict with ``next``, ``data`` (list of indicator objects), and ``status``.
    """
    _ = tql
    return {
        'next': (
            'https://success.threatconnect.com/api/v3/indicators?'
            'tql=indicatorActive%3Dtrue&resultStart=2&resultLimit=2'
        ),
        'data': [
            {
                'id': 2251799817155114,
                'dateAdded': '2025-03-26T19:01:41Z',
                'ownerId': 37,
                'ownerName': 'Firebog Prigent Malware Domains',
                'webLink': 'https://success.threatconnect.com/#/details/indicators/2251799817155114',
                'type': 'Host',
                'lastModified': '2026-05-14T21:31:23Z',
                'rating': 3.00,
                'confidence': 75,
                'summary': 'telegwryips.fit',
                'privateFlag': False,
                'active': True,
                'activeLocked': False,
                'hostName': 'telegwryips.fit',
                'dnsActive': False,
                'whoisActive': False,
                'legacyLink': (
                    'https://success.threatconnect.com/auth/indicators/details/host.xhtml?'
                    'host=telegwryips.fit&owner=Firebog+Prigent+Malware+Domains'
                ),
            },
            {
                'id': 2251799817155104,
                'dateAdded': '2025-03-26T19:01:41Z',
                'ownerId': 37,
                'ownerName': 'Firebog Prigent Malware Domains',
                'webLink': 'https://success.threatconnect.com/#/details/indicators/2251799817155104',
                'type': 'Host',
                'lastModified': '2026-05-14T21:31:23Z',
                'rating': 3.00,
                'confidence': 75,
                'summary': 'telegwryi.kim',
                'privateFlag': False,
                'active': True,
                'activeLocked': False,
                'hostName': 'telegwryi.kim',
                'dnsActive': False,
                'whoisActive': False,
                'legacyLink': (
                    'https://success.threatconnect.com/auth/indicators/details/host.xhtml?'
                    'host=telegwryi.kim&owner=Firebog+Prigent+Malware+Domains'
                ),
            },
        ],
        'status': 'Success',
    }


def summaries_to_csv(rows: list[dict[str, Any]]) -> str:
    """Build a one-column CSV (header ``summary``) from indicator dicts."""
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(['summary'])
    for row in rows:
        writer.writerow([row.get('summary', '')])
    return buf.getvalue()


class App(JobApp):
    """ThreatConnect Exchange App."""

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        # publishOutFiles docs mention tc_output_path; TcEx PathModel uses tc_out_path.
        payload = query_indicators_by_tql_stub(self.in_.indicator_tql)
        data = payload.get('data') or []
        if not isinstance(data, list):
            data = []

        csv_body = summaries_to_csv(data)
        out_dir = Path(self.in_.tc_out_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / OUTPUT_CSV
        out_path.write_text(csv_body, encoding='utf-8')
        self.log.info('feature=app, event=wrote-csv, rows=%s, path=%s', len(data), out_path)
