# AlienVault OTX - Subscribed Pulses

# Release Notes

### 1.0.0 (2026-07-20)

* Initial release: fetch AlienVault OTX subscribed pulses (`modified_since` cursor)
* Batch-import Reports with associated malware, adversaries, and indicators
* Persist `last_modified` between runs via `results_tc` (default first run: `30 days ago`)


# Description

Organization Job App that fetches subscribed pulses from AlienVault OTX and
imports Reports (with associated malware, adversaries, and indicators) into
ThreatConnect via batch.

### Inputs

  **ThreatConnect Owner** *(Choice)*
  The destination Owner in the ThreatConnect Platform.

  **OTX API Key** *(String / Keychain)*
  AlienVault OTX API key (`X-OTX-API-KEY`).

  **Last Modified** *(String, optional)*
  Cursor for OTX `modified_since`. Default / first run: `30 days ago` (relative
  expression). Also accepts ISO-8601 datetimes. Empty falls back to 30 days.
  After a successful run the App writes an ISO cursor via
  `results_tc('last_modified', ...)`; on the platform ThreatConnect feeds that
  value back as the next job input.

  **Threat Rating / Confidence** *(String)*
  Applied to imported indicators (defaults 3 / 50).

### Local run

1. Install dependencies: `tcex deps`.
2. Put ThreatConnect credentials in `.env`.
3. Set app values in `app_inputs.json` (including `otx_api_key`;
   `last_modified` defaults to `30 days ago`).
4. Run: `tcex run`

After a successful local run, the cursor is written to `results.tc` under
`tc_out_path` (often `log/`). Copy that `last_modified` value into
`app_inputs.json` for the next local incremental run if desired.
