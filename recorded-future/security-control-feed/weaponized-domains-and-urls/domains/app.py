"""ThreatConnect Job App"""

import json
from pathlib import Path
from urllib.parse import quote

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp

RF_SCF_BASE = 'https://api.recordedfuture.com/fusion/v3/files/'
RF_SCF_PATH = '/public/prevent/weaponized_domains.json'
MAPPING_PATH = Path(__file__).resolve().parent / 'mapping.json'
BATCH_CHUNK = 10_000
MAX_TAG_LENGTH = 128


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""
        self.tcex.session.external.base_url = RF_SCF_BASE

    def run(self):
        """Download Fusion file, map records, and batch import into ThreatConnect."""
        mapping = json.loads(MAPPING_PATH.read_text())
        records = self._load_records(mapping)
        imported = 0
        for offset in range(0, len(records), BATCH_CHUNK):
            chunk = records[offset : offset + BATCH_CHUNK]
            self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
            for rec in chunk:
                if isinstance(rec, dict):
                    imported += self._import_record(rec, mapping)
            self._submit()
        self.exit_message = f'Imported {imported} records from {RF_SCF_PATH}.'

    def _load_records(self, mapping: dict) -> list:
        """Fetch and parse the Fusion JSON file into a record list."""
        encoded_endpoint = quote(RF_SCF_PATH, safe='')
        headers = {
            'Accept': 'application/octet-stream',
            'X-RFToken': self.in_.rf_token.value,
        }
        self.log.info('requesting-fusion-file endpoint="%s"', encoded_endpoint)
        with self.tcex.session.external as session:
            response = session.get(f'/{encoded_endpoint}', headers=headers)
        if not response.ok:
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f'Fusion file request failed with status {response.status_code}',
            )
        try:
            payload = json.loads(response.content)
        except json.JSONDecodeError as ex:
            self.tcex.exit.exit(ExitCode.FAILURE, f'Invalid JSON in Fusion file: {ex}')

        records_key = mapping.get('records_key', 'results')
        if isinstance(payload, list):
            records = payload
        elif isinstance(payload, dict):
            records = payload.get(records_key) or []
        else:
            records = []
        if not records:
            self.tcex.exit.exit(ExitCode.FAILURE, 'Fusion file did not contain records.')
        self.log.info('Loaded %d records from Fusion %s', len(records), RF_SCF_PATH)
        return records

    def _import_record(self, rec: dict, mapping: dict) -> int:
        """Create mapped indicators and groups for one Fusion record."""
        count = 0
        for rule in mapping.get('indicators') or []:
            value = rec.get(rule.get('rf_field'))
            if not value:
                continue
            indicator = self.batch.indicator(
                rule['tc_type'],
                value,
                rating=self.in_.rating,
                confidence=self.in_.confidence,
            )
            self._apply_metadata(indicator, rec, rule)
            self.batch.save(indicator)
            count += 1
        for rule in mapping.get('groups') or []:
            name = rec.get(rule['rf_field']) if rule.get('rf_field') else rule.get('name')
            if not name:
                continue
            group = self.batch.group(rule['tc_type'], str(name))
            self._apply_metadata(group, rec, rule)
            self.batch.save(group)
            count += 1
        return count

    def _apply_metadata(self, obj, rec: dict, rule: dict) -> None:
        """Apply tag, attributes, and truthy-key tags from a mapping rule."""
        if rule.get('tag'):
            self._tag(obj, rule['tag'])
        for attr in rule.get('attributes') or []:
            raw = rec.get(attr.get('rf_field'))
            if raw in (None, ''):
                continue
            if attr.get('format') == 'datetime':
                try:
                    raw = self.tcex.util.any_to_datetime(raw).strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception as ex:
                    self.log.warning(
                        'datetime-conversion-failed field=%s value=%r error=%s',
                        attr.get('rf_field'),
                        raw,
                        ex,
                    )
                    continue
            obj.attribute(attr['tc_type'], raw)
        flags = rec.get(rule.get('tags_from_truthy_keys') or '')
        if isinstance(flags, dict):
            for key, enabled in flags.items():
                if enabled:
                    self._tag(obj, key)

    def _tag(self, obj, value) -> None:
        """Add a truncated tag to a batch object."""
        text = str(value).strip()
        if not text:
            return
        if len(text) > MAX_TAG_LENGTH:
            text = text[: MAX_TAG_LENGTH - 3] + '...'
        obj.tag(text)

    def _submit(self) -> None:
        """Submit the current batch job."""
        batch_response = self.batch.submit_all()
        self.batch.close()
        errors = []
        success = 0
        for item in batch_response or []:
            errors.extend(item.get('errors', []))
            success += item.get('successCount', 0)
        if errors:
            self.log.error('batch submission reported %d errors', len(errors))
            self.log.error('batch submission error: %s', errors[0])
        self.log.info('batch submission successful with %d items', success)
