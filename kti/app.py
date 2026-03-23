"""ThreatConnect Job App"""

import json
import re
from urllib.parse import quote

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

# Recorded Future Fusion v3 files API (path segment is URL-encoded; appended after base).
RF_FUSION_FILES_BASE = 'https://api.recordedfuture.com/fusion/v3/files/'
TOR_FUSION_FILE_PATH = '/public/policy/tor_ips.json'

# ThreatConnect tag length guard (conservative; platform limits vary by version).
MAX_TAG_LENGTH = 128

# Log at most this many characters of an HTTP error body (avoid huge or sensitive payloads).
HTTP_ERROR_BODY_LOG_MAX = 500

_DUPLICATE_BATCH_SUBSTRING = 'Found duplicate indicator in batch job file'


def normalize_tor_nodes_payload(parsed: object) -> list:
    """Return a list of node dicts from Fusion JSON (array or common wrappers).

    Exposed at module level for unit tests.
    """
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ('data', 'records', 'nodes', 'ips', 'tor_ips', 'items'):
            val = parsed.get(key)
            if isinstance(val, list):
                return val
        if any(k in parsed for k in ('ip', 'ipAddress', 'address', 'value')):
            return [parsed]
    return []


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self) -> None:
        """Perform prep/setup logic."""
        self.tcex.session.external.base_url = RF_FUSION_FILES_BASE

    def run(self) -> None:
        """Run main App logic."""
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
        self._load_tor_nodes()
        self._batch_submit()

    def _load_tor_nodes(self) -> None:
        """Load Tor nodes from Recorded Future Fusion public policy file."""
        encoded_endpoint = quote(TOR_FUSION_FILE_PATH, safe='')

        headers = {
            'Accept': 'application/octet-stream',
            'X-RFToken': self.in_.rf_token.value,
        }
        self.tcex.log.info('requesting-fusion-file endpoint="%s"', encoded_endpoint)

        try:
            with self.tcex.session.external as session:
                response = session.get(f'/{encoded_endpoint}', headers=headers)
        except Exception:
            self.tcex.log.exception('Failed to retrieve Fusion Tor file')
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Failed to retrieve Fusion Tor file (see logs).',
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
            self.tcex.log.error('Fusion Tor file is not valid UTF-8: %s', ex)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Fusion Tor file is not valid UTF-8.',
            )
        except json.JSONDecodeError as ex:
            self.tcex.log.error('Invalid JSON in Fusion Tor file: %s', ex)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'Invalid JSON in Fusion Tor file: {ex}',
            )

        tor_nodes = normalize_tor_nodes_payload(parsed)
        if not tor_nodes:
            self.tcex.log.error(
                'Fusion Tor payload had no node list (type=%s)',
                type(parsed).__name__,
            )
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                'Fusion Tor file did not contain a recognizable list of nodes.',
            )

        self.tcex.log.info(
            'Loaded %d Tor node records from Fusion %s',
            len(tor_nodes),
            TOR_FUSION_FILE_PATH,
        )

        for node in tor_nodes:
            if not isinstance(node, dict):
                self.tcex.log.warning('Skipping non-object entry: %r', node)
                continue
            ip = (
                node.get('ip')
                or node.get('ipAddress')
                or node.get('address')
                or node.get('value')
            )
            if not ip:
                self.tcex.log.warning('Skipping entry without IP field: %r', node)
                continue
            ioc = {
                'value': ip,
                'flags': node.get('flags'),
                'name': node.get('name'),
            }
            self._batch_save_ioc(ioc)

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

    def _truncate_tag_value(self, value: object) -> str:
        """Return tag string truncated to MAX_TAG_LENGTH."""
        text = str(value).strip()
        if len(text) <= MAX_TAG_LENGTH:
            return text
        return text[: MAX_TAG_LENGTH - 3] + '...'

    def _batch_save_ioc(self, ioc: dict) -> None:
        """Save IOC to batch."""
        indicator = self.batch.indicator(
            'Address',
            ioc['value'],
            rating=self.in_.rating,
            confidence=self.in_.confidence,
        )

        indicator.tag('Tor Node')
        if ioc.get('flags'):
            tag = f'flag:{self._truncate_tag_value(ioc["flags"])}'
            indicator.tag(tag)
        if ioc.get('name'):
            tag = f'name:{self._truncate_tag_value(ioc["name"])}'
            indicator.tag(tag)

        self.batch.save(indicator)
