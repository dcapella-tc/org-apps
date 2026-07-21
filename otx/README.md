# AlienVault OTX - Subscribed Pulses

# Release Notes

### 1.1.1 (2026-07-21)

* Precheck ThreatConnect batch write access on the destination owner before fetching OTX
* Batch item-level errors are warnings only; successful submits still advance `last_run`

### 1.1.0 (2026-07-20)

* Rename Last Modified input / `results_tc` cursor to **Last Run** (`last_run`) for clearer operator UX
* Note: existing Jobs that stored `last_modified` in results.tc do not auto-migrate; set Last Run once after upgrade

### 1.0.3 (2026-07-20)

* Feed Deployer: show ThreatConnect Owner on Parameters (restore job default); if you rename the Source, set Owner to the same name

### 1.0.2 (2026-07-20)

* Feed Deployer: set Job `tc_owner` from the Source name entered on Deploy (supports custom Source names)

### 1.0.1 (2026-07-20)

* Feed Deployer: show API key, cursor, ratings, and log level on the Parameters tab
* Pin `tc_owner` to the created Source in the job template (fixes missing-owner validation)

### 1.0.0 (2026-07-20)

* Initial release: fetch AlienVault OTX subscribed pulses (`modified_since` cursor)
* Batch-import Reports with associated malware, adversaries, and indicators
* Persist `last_modified` between runs via `results_tc` (default first run: `30 days ago`)


# Description

Organization Job App that fetches subscribed pulses from AlienVault OTX and
imports Reports (with associated malware, adversaries, and indicators) into
ThreatConnect via batch.

### Deploy

After installing the App via TC Exchange, a System Administrator can use Feed
Deployer (**Settings → TC Exchange Settings → Deploy**) to create the Source
and scheduled Job.

Feed Deployer Parameters include ThreatConnect Owner, API key, Last Run
lookback/cursor, threat rating, confidence, and logging level. Owner defaults to
`AlienVault OTX - Subscribed Pulses`. If you rename the Source on the Source
tab (for example with a Capella prefix), set **ThreatConnect Owner** on
Parameters to that **exact** same name. You can enter the API key in
Parameters, or leave the job default and create an Organization Keychain
variable named `OTX API Key`.

### ThreatConnect permissions

The API user / token used by the Job must have **create** permission on the
destination Source for: Indicators, Groups, Attributes, Tags, and Security
Labels. The Job prechecks write access with `POST /v2/batch` before calling
OTX; a 401 fails immediately without advancing `last_run`. After import,
batch item-level errors (e.g. invalid URLs) are logged as warnings and do
not fail the Job; `last_run` still advances when submit returns normally.

### Inputs

  **ThreatConnect Owner** *(Choice)*
  The destination Owner in the ThreatConnect Platform.

  **OTX API Key** *(String / Keychain)*
  AlienVault OTX API key (`X-OTX-API-KEY`).

  **Last Run** *(String, optional)*
  First-run lookback or ISO cursor used for OTX `modified_since`. Default /
  first run: `30 days ago` (relative expression; e.g. `90 days ago` also
  works). Also accepts ISO-8601 datetimes. Empty falls back to 30 days.
  After a successful run the App writes an ISO cursor via
  `results_tc('last_run', ...)`; on the platform ThreatConnect feeds that
  value back as the next job input.

  **Threat Rating / Confidence** *(String)*
  Applied to imported indicators (defaults 3 / 50).

### Local run

1. Install dependencies: `tcex deps`.
2. Put ThreatConnect credentials in `.env`.
3. Set app values in `app_inputs.json` (including `otx_api_key`;
   `last_run` defaults to `30 days ago`).
4. Run: `tcex run`

After a successful local run, the cursor is written to `results.tc` under
`tc_out_path` (often `log/`). Copy that `last_run` value into
`app_inputs.json` for the next local incremental run if desired.
