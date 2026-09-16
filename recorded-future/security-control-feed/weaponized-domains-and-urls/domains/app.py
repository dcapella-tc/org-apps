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
APP_DIR = Path(__file__).resolve().parent
MAPPING_PATH = APP_DIR / 'mapping.json'
STATE_PATH = APP_DIR / 'ingest_state.json'
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

    def _record_id(self, rec: dict, mapping: dict) -> str | None:
        """Return the primary indicator value used as a state key."""
        for rule in mapping.get('indicators') or []:
            value = rec.get(rule.get('rf_field'))
            if value:
                return str(value)
        return None

    def _fingerprint(self, rec: dict) -> str:
        """Return a stable hash of one Fusion record."""
        payload = {k: v for k, v in rec.items() if k != '_uuid'}
        blob = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(blob).hexdigest()

    def _fingerprints(self, records: list, mapping: dict) -> dict[str, str]:
        """Map record id -> fingerprint for dict records with an id."""
        fps = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            rec_id = self._record_id(rec, mapping)
            if rec_id:
                fps[rec_id] = self._fingerprint(rec)
        return fps

    def _load_state(self) -> dict:
        """Load prior ingest fingerprints if present."""
        if not STATE_PATH.is_file():
            return {}
        try:
            return json.loads(STATE_PATH.read_text())
        except (OSError, json.JSONDecodeError) as ex:
            self.log.warning('Could not read ingest state: %s', ex)
            return {}

    def _save_state(self, records: list, mapping: dict) -> None:
        """Persist current fingerprints so the next run can skip unchanged records."""
        STATE_PATH.write_text(
            json.dumps({'fps': self._fingerprints(records, mapping)}, separators=(',', ':'))
        )

    def _write_since_date(self, records: list) -> None:
        """Publish max last_seen for ThreatConnect job chaining."""
        last_seen = [
            str(rec.get('last_seen') or '')
            for rec in records
            if isinstance(rec, dict) and rec.get('last_seen')
        ]
        if not last_seen:
            return
        max_last_seen = max(last_seen)
        try:
            self.tcex.app.results_tc('since_date', max_last_seen)
        except Exception as ex:
            self.log.debug('results_tc since_date skipped: %s', ex)

    def _record_uuid(self, rec: dict) -> str:
        """Return a uuid5 fingerprint of the Fusion record (excluding _uuid)."""
        payload = {k: v for k, v in rec.items() if k != '_uuid'}
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return str(uuid.uuid5(uuid.NAMESPACE_URL, canonical))

    def _existing_uuids(self) -> set:
        """Return UUID attribute values already present in the destination owner."""
        attrs = self.tcex.api.tc.v3.indicator_attributes(params={'resultLimit': 10000})
        attrs.filter.owner_name(TqlOperator.EQ, self.in_.tc_owner)
        attrs.filter.type_name(TqlOperator.EQ, 'UUID')
        return {a.model.value for a in attrs if a.model.value}

    def _drop_seen(self, records: list) -> list:
        """Remove records whose UUID already exists on a Host in the owner."""
        existing = self._existing_uuids()
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

    def _pending_records(self, records: list, mapping: dict) -> list:
        """Return records that are new or changed since the last successful run."""
        prev_fps = (self._load_state() or {}).get('fps') or {}
        if prev_fps:
            pending = []
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                rec_id = self._record_id(rec, mapping)
                if not rec_id or prev_fps.get(rec_id) != self._fingerprint(rec):
                    pending.append(rec)
            return pending

        since_date = str(getattr(self.in_, 'since_date', '') or '').strip()
        if since_date:
            pending = []
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                last_seen = str(rec.get('last_seen') or '')
                if last_seen > since_date:
                    pending.append(rec)
            return pending

        return [rec for rec in records if isinstance(rec, dict)]

    def run(self):
        """Download Fusion file, map records, and batch import into ThreatConnect."""
        mapping = json.loads(MAPPING_PATH.read_text())
        records = self._load_records(mapping)
        for rec in records:
            if isinstance(rec, dict):
                rec['_uuid'] = self._record_uuid(rec)
        records = self._drop_seen(records)
        pending = self._pending_records(records, mapping)
        if not pending:
            self._save_state(records, mapping)
            self._write_since_date(records)
            self.exit_message = (
                f'No new or updated records in {RF_SCF_PATH}; skipped batch import.'
            )
            return

        self.log.info('Importing %d of %d records', len(pending), len(records))
        imported = 0
        for offset in range(0, len(pending), BATCH_CHUNK):
            chunk = pending[offset : offset + BATCH_CHUNK]
            self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
            for rec in chunk:
                imported += self._import_record(rec, mapping)
            self._submit()
        self._save_state(records, mapping)
        self._write_since_date(records)
        self.exit_message = (
            f'Imported {imported} of {len(records)} records from {RF_SCF_PATH}.'
        )

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
