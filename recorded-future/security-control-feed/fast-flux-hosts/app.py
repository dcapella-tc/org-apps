"""ThreatConnect Job App"""

import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


# Recorded Future Fusion v3 files API (path segment is URL-encoded; appended after base).
RF_SCF_BASE = 'https://api.recordedfuture.com/fusion/v3/files/'
RF_SCF_PATH = '/public/detect/fflux_ips.json'

# ThreatConnect tag length guard (conservative; platform limits vary by version).
MAX_TAG_LENGTH = 128

# Log at most this many characters of an HTTP error body (avoid huge or sensitive payloads).
HTTP_ERROR_BODY_LOG_MAX = 500

_DUPLICATE_BATCH_SUBSTRING = 'Found duplicate indicator in batch job file'


def normalize_fusion_records_payload(parsed: object) -> list:
    """Return a list of record dicts from Fusion JSON (array or common wrappers)."""
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ('data', 'records', 'nodes', 'ips', 'items'):
            val = parsed.get(key)
            if isinstance(val, list):
                return val
        if any(k in parsed for k in ('ip', 'ipAddress', 'address', 'value')):
            return [parsed]
    return []


def _coerce_last_seen_datetime(raw: object) -> datetime | None:
    """Parse last-seen from Fusion (epoch ms, seconds, or ISO string)."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw / 1000, tz=timezone.utc)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            return None
    return None


def _format_last_seen_for_tc(dt: datetime) -> str:
    """Format datetime as UTC ISO string for ThreatConnect batch (JSON-serializable)."""
    if dt.tzinfo is not None:
        utc = dt.astimezone(timezone.utc)
    else:
        utc = dt.replace(tzinfo=timezone.utc)
    return utc.strftime('%Y-%m-%dT%H:%M:%SZ')


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        self.tcex.session.external.base_url = RF_SCF_BASE

    def run(self):
        """Run main App logic."""
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
        self._load_fast_flux_hosts()
        self._batch_submit()

    def _load_fast_flux_hosts(self) -> None:
        """Load Fast Flux host IPs from Recorded Future Fusion public detect file."""
        encoded_endpoint = quote(RF_SCF_PATH, safe='')

        headers = {
            'Accept': 'application/octet-stream',
            'X-RFToken': self.in_.rf_token.value,
        }
        self.tcex.log.info('requesting-fusion-file endpoint="%s"', encoded_endpoint)

        try:
            with self.tcex.session.external as session:
                response = session.get(f'/{encoded_endpoint}', headers=headers)
        except Exception:
            self.tcex.log.exception('Failed to retrieve Fusion Fast Flux file')
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Failed to retrieve Fusion Fast Flux file (see logs).',
            )

        if not response.ok:
            self.tcex.log.error(
                'Fusion file request failed with status %s', response.status_code
            )
            body_preview = ''
            try:
                raw = response.text[:HTTP_ERROR_BODY_LOG_MAX]
                body_preview = raw if raw else ''
            except Exception:
                pass
            if body_preview:
                self.tcex.log.error(
                    'Fusion response body (truncated): %s',
                    body_preview,
                )
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'Fusion file request failed with status {response.status_code}',
            )

        try:
            if isinstance(response.content, bytes):
                raw_text = response.content.decode('utf-8')
            else:
                raw_text = str(response.content)
            parsed = json.loads(raw_text)
        except UnicodeDecodeError as ex:
            self.tcex.log.error('Fusion Fast Flux file is not valid UTF-8: %s', ex)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Fusion Fast Flux file is not valid UTF-8.',
            )
        except json.JSONDecodeError as ex:
            self.tcex.log.error('Invalid JSON in Fusion Fast Flux file: %s', ex)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'Invalid JSON in Fusion Fast Flux file: {ex}',
            )

        records = normalize_fusion_records_payload(parsed)
        if not records:
            self.tcex.log.error(
                'Fusion Fast Flux payload had no record list (type=%s)',
                type(parsed).__name__,
            )
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Fusion Fast Flux file did not contain a recognizable list of records.',
            )

        self.tcex.log.info(
            'Loaded %d Fast Flux host records from Fusion %s',
            len(records),
            RF_SCF_PATH,
        )

        for record in records:
            if not isinstance(record, dict):
                self.tcex.log.warning('Skipping non-object entry: %r', record)
                continue
            ip = (
                record.get('ip')
                or record.get('ipAddress')
                or record.get('address')
                or record.get('value')
            )
            if not ip:
                self.tcex.log.warning('Skipping entry without IP field: %r', record)
                continue
            indicator: dict = {'value': ip}
            if 'lastSeen' in record:
                indicator['last_seen'] = record['lastSeen']
            elif 'last_seen' in record:
                indicator['last_seen'] = record['last_seen']
            self._batch_add_indicator(indicator)

    def _batch_add_indicator(self, indicator: dict) -> None:
        """Add indicator to batch job."""
        ip = self.batch.indicator(
            'Address',
            indicator['value'],
            rating=self.in_.rating,
            confidence=self.in_.confidence,
        )
        ip.tag('Fast Flux Host')

        last_seen_raw = indicator.get('last_seen')
        if last_seen_raw is not None and last_seen_raw != '':
            last_seen_dt = _coerce_last_seen_datetime(last_seen_raw)
            if last_seen_dt is not None:
                ip.attribute(
                    'Last Seen',
                    _format_last_seen_for_tc(last_seen_dt),
                )
            else:
                self.tcex.log.warning(
                    'Skipping unparseable last_seen for %r: %r',
                    indicator.get('value'),
                    last_seen_raw,
                )

        self.batch.save(ip)

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
                f'Imported {success} Fast Flux address indicators '
                f'({len(errors)} duplicate warnings in log).'
            )
            return

        self.tcex.log.info('No errors found.')
        if success:
            self.tcex.log.info(
                'App.run: batch submission successful with %d items', success
            )
            self.exit_message = f'Imported {success} Fast Flux address indicators.'
        else:
            self.tcex.log.warning('No successes found.')
            self.exit_message = 'Batch completed with no successes.'
