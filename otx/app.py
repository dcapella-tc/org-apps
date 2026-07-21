"""ThreatConnect Job App"""

from datetime import UTC, datetime
from pathlib import Path

from tcex import TcEx
from tcex.exit import ExitCode

from helper.otx import Otx
from helper.otx_batch_pulse import import_pulse
from helper.otx_batch_status import summarize_batch_errors
from helper.otx_dates import format_last_run_cursor, parse_last_run_input
from helper.otx_parse import extract_pulses
from helper.otx_tc_precheck import assert_owner_batch_writable
from job_app import JobApp  # Import default Job App Class (Required)


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)

    def setup(self):
        """Perform prep/setup logic."""
        # Base URL for subsequent OTX API calls (path-only requests).
        self.tcex.session.external.base_url = 'https://otx.alienvault.com/api/v1/'

    def run(self):
        """Run main App logic."""
        run_started = datetime.now(tz=UTC)
        try:
            window_start = parse_last_run_input(
                str(getattr(self.in_, 'last_run', '') or '')
            )
        except ValueError as exc:
            self.tcex.exit.exit(ExitCode.FAILURE, str(exc))

        try:
            assert_owner_batch_writable(self.tcex.session.tc, str(self.in_.tc_owner))
        except PermissionError as exc:
            self.tcex.exit.exit(ExitCode.FAILURE, str(exc))
        self.log.info('tc-precheck batch create ok owner=%s', self.in_.tc_owner)

        otx = Otx(self.tcex, api_key=self.in_.otx_api_key.value)
        out_dir = Path(self.in_.tc_out_path)

        payload = otx.fetch_with_widening_window(window_start, out_dir=out_dir)
        pulses = extract_pulses(payload)
        pulse_count = len(pulses)

        json_path = out_dir / 'otx_pulses_raw.json'
        csv_path = out_dir / 'otx_pulses_sheet.csv'
        self.log.info(
            'saved-otx-inspection json=%s csv=%s count=%s',
            json_path,
            csv_path,
            pulse_count,
        )

        rating = str(getattr(self.in_, 'tc_threat_rating', '3') or '3')
        confidence = str(getattr(self.in_, 'tc_confidence', '50') or '50')

        total_adversaries = 0
        total_malware = 0
        total_vulnerabilities = 0
        total_indicators = 0
        total_skipped = 0
        for pulse in pulses:
            stats = import_pulse(
                self.batch,
                pulse,
                rating=rating,
                confidence=confidence,
                log=self.log,
            )
            total_adversaries += stats['adversaries']
            total_malware += stats['malware']
            total_vulnerabilities += stats['vulnerabilities']
            total_indicators += stats['indicators']
            total_skipped += stats['skipped_indicators']

        batch_status: list = []
        submit_error: RuntimeError | None = None
        try:
            batch_status = self.batch.submit_all()
        except RuntimeError as exc:
            self.log.warning('batch-submit-exception=%s', exc)
            submit_error = exc
        self.batch.close()

        if submit_error is not None:
            # Uncertain write — warn only, do not advance last_run.
            self.exit_message = (
                f'Queued {pulse_count} OTX pulse(s); batch submit raised '
                f'({submit_error}); last_run cursor not advanced.'
            )
            return

        self.log.info('batch-status=%s', batch_status)
        error_summary = summarize_batch_errors(batch_status)
        if error_summary:
            self.log.warning('batch-item-errors %s', error_summary)

        cursor = format_last_run_cursor(run_started)
        self.tcex.app.results_tc('last_run', cursor)
        self.log.info('saved-last-run-cursor=%s', cursor)

        self.exit_message = (
            f'Queued {pulse_count} OTX pulse(s) as Reports; '
            f'{total_adversaries} adversaries; {total_malware} malware; '
            f'{total_vulnerabilities} vulnerabilities; '
            f'{total_indicators} indicators ({total_skipped} skipped); '
            f'batch submit completed.'
        )
        if error_summary:
            self.exit_message += f' Warning: {error_summary}'
