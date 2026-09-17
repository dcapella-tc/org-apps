"""ThreatConnect Job App"""

import hashlib
import json
import uuid
from pathlib import Path
from urllib.parse import quote

from tcex import TcEx
from tcex.api.tc.v3.tql.tql_operator import TqlOperator
from tcex.exit import ExitCode

from job_app import JobApp

RF_SCF_BASE = 'https://api.recordedfuture.com/fusion/v3/files/'
RF_SCF_PATH = '/public/prevent/weaponized_domains.json'
MAPPING_PATH = Path(__file__).resolve().parent / 'mapping.json'
BATCH_CHUNK = 10_000
UUID_TQL_CHUNK = 500
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
        records, feed_hash = self._load_records(mapping)
        prev_hash = str(getattr(self.in_, 'feed_hash', '') or '').strip()
        if prev_hash and prev_hash == feed_hash:
            self._write_feed_hash(feed_hash)
            self.log.info('Fusion file unchanged; skipped ingest.')
            self.exit_message = 'Fusion file unchanged; skipped ingest.'
            return

        for rec in records:
            if isinstance(rec, dict):
                rec['_uuid'] = self._record_uuid(rec)
        records = self._drop_seen(records)
        if not records:
            self._write_feed_hash(feed_hash)
            self.exit_message = (
                f'No new or updated records in {RF_SCF_PATH}; skipped batch import.'
            )
            return

        imported = 0
        for offset in range(0, len(records), BATCH_CHUNK):
            chunk = records[offset : offset + BATCH_CHUNK]
            self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
            for rec in chunk:
                if isinstance(rec, dict):
                    imported += self._import_record(rec, mapping)
            self._submit()
        self._write_feed_hash(feed_hash)
        self.exit_message = f'Imported {imported} records from {RF_SCF_PATH}.'

    def _load_records(self, mapping: dict) -> tuple:
        """Fetch and parse the Fusion JSON file into a record list and file hash."""
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
        feed_hash = hashlib.sha256(response.content).hexdigest()
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
        self.log.info(
            'Loaded %d records from Fusion %s hash=%s',
            len(records),
            RF_SCF_PATH,
            feed_hash,
        )
        return records, feed_hash

    def _write_feed_hash(self, feed_hash: str) -> None:
        """Persist the Fusion file hash for the next job run."""
        try:
            self.tcex.app.results_tc('feed_hash', feed_hash)
        except Exception as ex:
            self.log.debug('results_tc feed_hash skipped: %s', ex)

    def _record_uuid(self, rec: dict) -> str:
        """Return a uuid5 fingerprint of the Fusion record (excluding _uuid)."""
        payload = {k: v for k, v in rec.items() if k != '_uuid'}
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return str(uuid.uuid5(uuid.NAMESPACE_URL, canonical))

    def _existing_uuids(self, incoming: set) -> set:
        """Return which incoming UUID values already exist in the destination owner."""
        if not incoming:
            return set()
        values = list(incoming)
        existing = set()
        chunks = 0
        for offset in range(0, len(values), UUID_TQL_CHUNK):
            chunk = values[offset : offset + UUID_TQL_CHUNK]
            chunks += 1
            attrs = self.tcex.api.tc.v3.indicator_attributes(params={'resultLimit': 10000})
            attrs.filter.owner_name(TqlOperator.EQ, self.in_.tc_owner)
            attrs.filter.type_name(TqlOperator.EQ, 'UUID')
            attrs.filter.text(TqlOperator.IN, chunk)
            existing.update(a.model.value for a in attrs if a.model.value)
        self.log.info(
            'uuid-tql chunks=%d incoming=%d existing=%d',
            chunks,
            len(incoming),
            len(existing),
        )
        return existing

    def _drop_seen(self, records: list) -> list:
        """Remove records whose UUID already exists on a Host in the owner."""
        incoming = {
            rec.get('_uuid')
            for rec in records
            if isinstance(rec, dict) and rec.get('_uuid')
        }
        existing = self._existing_uuids(incoming)
        kept = [
            rec
            for rec in records
            if not isinstance(rec, dict) or rec.get('_uuid') not in existing
        ]
        self.log.info(
            'uuid-filter loaded=%d existing=%d kept=%d',
            len(records),
            len(existing),
            len(kept),
        )
        return kept

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
        """Apply tags, attributes, and truthy-key tags from a mapping rule."""
        for tag in rule.get('tags') or []:
            self._tag(obj, tag)
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
