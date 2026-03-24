"""ThreatConnect Job App"""

from datetime import datetime
import re

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


# Recorded Future Fusion v3 files API (path segment is URL-encoded; appended after base).
RF_FUSION_FILES_BASE = 'https://api.recordedfuture.com/fusion/v3/files/'
TOR_FUSION_FILE_PATH = '/public/detect/fflux_ips.json'

# ThreatConnect tag length guard (conservative; platform limits vary by version).
MAX_TAG_LENGTH = 128

# Log at most this many characters of an HTTP error body (avoid huge or sensitive payloads).
HTTP_ERROR_BODY_LOG_MAX = 500

_DUPLICATE_BATCH_SUBSTRING = 'Found duplicate indicator in batch job file'



class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        self.tcex.session.external.base_url = RF_FUSION_FILES_BASE

    def run(self):
        """Run main App logic."""
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
        # To Do: Helper function — Get the Fast Flux Hosts from Recorded Future
        # To Do: Helper function — Loop through each record of the Fast Flux Hosts and add to batch job using _batch_add_indicator
        self._batch_submit()

    def _batch_add_indicator(self, indicator: dict) -> None:
        """Add indicator to batch job."""
        ip = self.batch.indicator(
            'Address'
            ,indicator['value']
            ,rating=self.in_.rating
            ,confidence=self.in_.confidence
        )
        ip.tag("Fast Flux Host")

        if indicator.get("lastSeen"):
            last_seen = datetime.fromisoformat(indicator["lastSeen"])
            ip.attribute("Last Seen", last_seen)


    def _batch_submit(self) -> None:
        """Submit batch job and handle errors."""
        batch_response = self.batch.submit_all()
        self.tcex.log.debug('batch_response: %s', batch_response)
        self.batch.close()

        errors: list = []
        success = 0
        for item in batch_response:
            errors.extend(item.get('errors', []))
            success += item.get('successCount', 0)

        if errors:
            self.tcex.log.error(
                'App.run: batch submission reported %d errors', len(errors)
            )

            error_count = 0
            known_errors: list[str] = []
            for error in errors:
                error_count += 1
                if error_count == 100:
                    break
                error_reason = error.get('errorReason', '')
                if _DUPLICATE_BATCH_SUBSTRING in error_reason:
                    if _DUPLICATE_BATCH_SUBSTRING in known_errors:
                        continue
                    known_error = _DUPLICATE_BATCH_SUBSTRING
                else:
                    try:
                        error_reason = error_reason.split('is not valid. ')[1]
                    except (IndexError, ValueError):
                        pass
                    known_error = re.sub(r"'[^']*'", '', error_reason).strip()
                    if known_error in known_errors:
                        continue
                known_errors.append(known_error)
                self.tcex.log.error('App.run: batch submission error: %s', error)

            non_duplicate_errors = [
                e
                for e in errors
                if _DUPLICATE_BATCH_SUBSTRING not in e.get('errorReason', '')
            ]
            if non_duplicate_errors:
                self.tcex.exit.exit(
                    ExitCode.FAILURE,
                    f'Batch completed with {len(non_duplicate_errors)} non-duplicate '
                    f'errors ({success} successes); see logs.',
                )
            self.tcex.log.warning(
                'Batch had only duplicate-indicator warnings; %d indicators succeeded',
                success,
            )
            self.exit_message = (
                f'Imported {success} Tor address indicators '
                f'({len(errors)} duplicate warnings in log).'
            )
            return

        self.tcex.log.info('No errors found.')
        if success:
            self.tcex.log.info(
                'App.run: batch submission successful with %d items', success
            )
            self.exit_message = f'Imported {success} Tor address indicators.'
        else:
            self.tcex.log.warning('No successes found.')
            self.exit_message = 'Batch completed with no successes.'


