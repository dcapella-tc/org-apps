"""ThreatConnect Job App"""

from pathlib import Path

from tcex import TcEx
from tcex.exit import ExitCode

from helper.otx import Otx
from helper.otx_api_key import resolve_otx_api_key
from helper.otx_dates import parse_last_modified_input
from helper.otx_parse import extract_pulses
from job_app import JobApp  # Import default Job App Class (Required)


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""
        # Base URL for subsequent OTX API calls (path-only requests).
        self.tcex.session.external.base_url = 'https://otx.alienvault.com/api/v1/'

    def run(self):
        """Run main App logic."""
        try:
            raw_key = getattr(self.in_.otx_api_key, 'value', self.in_.otx_api_key)
            api_key = resolve_otx_api_key(raw_key)
        except ValueError as exc:
            self.tcex.exit.exit(ExitCode.FAILURE, str(exc))

        otx = Otx(self.tcex, api_key=api_key)
        last_modified = parse_last_modified_input(
            str(getattr(self.in_, 'last_modified', '') or '')
        )
        out_dir = Path(self.in_.tc_out_path)

        payload = otx.fetch_with_widening_window(last_modified, out_dir=out_dir)
        pulse_count = len(extract_pulses(payload))
        json_path = out_dir / 'otx_pulses_raw.json'
        csv_path = out_dir / 'otx_pulses_sheet.csv'

        self.log.info(
            'saved-otx-inspection json=%s csv=%s count=%s',
            json_path,
            csv_path,
            pulse_count,
        )
        self.exit_message = (
            f'Downloaded {pulse_count} OTX pulse(s); '
            f'saved inspection files to {out_dir}.'
        )
