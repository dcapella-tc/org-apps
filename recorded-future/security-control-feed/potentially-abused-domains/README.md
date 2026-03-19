## Release Notes

### 1.0.0 (2026-03-19)

* Initial Release

# Potentially Abused Domains - Security Control Feed

ThreatConnect Organization App that ingests Recorded Future's Potentially Abused Domains (PAD) gzip feed and creates `Host` indicators in ThreatConnect, tagged and attributed for easy analyst triage.

## Description

At runtime, the app downloads the PAD feed from Recorded Future Fusion files API, streams/parses the gzip JSON payload, and then writes ThreatConnect indicators using TcEx batch submission.

For each feed record, it creates up to two `Host` indicators:

- One for the observed subdomain (`domain`)
- One for the parent/apex domain (`apex_domain`)

Each indicator is tagged as a "Potentially Abused Domain" and enriched with tags/attributes derived from the feed.

## Inputs

| Input | Type | Description |
|-------|------|-------------|
| `tc_owner` | Choice | The ThreatConnect owner into which indicators are written. |
| `rf_api_token` | Sensitive (String) | Recorded Future API token used for Fusion files API authentication (`X-RFToken`). |
| `tc_confidence` | String | Confidence value applied to created indicators. |
| `tc_threat_rating` | String | Threat rating value applied to created indicators. |
| `batch_limit` | Choice (e.g. `1`, `10`, `100`) | Number of batch submissions executed during the run in either mode. |
| `since_date` | String (optional) | Mode selector. If empty, app runs in initial/backfill behavior. If set, records with timestamps after this date are imported (ISO 8601 datetime or date). |

## Operation / Run Modes

The app chooses the mode based on `since_date`:

### `initial_run` behavior (`since_date` is empty)

- The app sets `mode="initial_run"`.
- It downloads the PAD gzip feed (`/public/prevent/new_domains_ctl.json.gz`) and fetches records ordered by timestamp descending (streaming).
- It submits a TcEx batch for up to two `Host` indicators per feed record and repeats the batch submission up to `batch_limit` times.

### `incremental_new` behavior (`since_date` is set)

- The app parses `since_date` and sets `mode="incremental_new"`.
- If `since_date` cannot be parsed, the app exits successfully without importing records.
- It fetches records whose `timestamp` is strictly greater than the cursor derived from `since_date`.
- It submits one batch per loop iteration, repeated up to `batch_limit` times.

## Recommended Workflow

- First run: leave `since_date` empty to backfill from newest records.
- Subsequent runs: reuse the app output `since_date` value as the next input cursor.

## Output in ThreatConnect

For each parsed PAD feed record, the app may create:

### Subdomain indicator (`domain`)

- Indicator type: `Host`
- Identifier: the feed `domain` value
- Tags:
  - `Potentially Abused Domain`
  - `Subdomain`
  - `Apex Domain:{apex_domain}`
- Attributes:
  - `Source`: `Potentially Abused Domains`
  - `Last Seen`: ISO 8601 UTC value derived from the feed `timestamp` (when parseable)
  - `Description`: full observed hostname (FQDN) for the specific subdomain
- Indicator confidence/rating:
  - `confidence` = `tc_confidence`
  - `rating` = `tc_threat_rating`

### Apex domain indicator (`apex_domain`)

- Indicator type: `Host`
- Identifier: the feed `apex_domain` value
- Tags:
  - `Potentially Abused Domain`
  - `Apex Domain`
  - `Subdomain:{domain}`
- Attributes:
  - `Source`: `Potentially Abused Domains`
  - `Description`: base registrable domain associated with the observed hostname
- Indicator confidence/rating:
  - `confidence` = `tc_confidence`
  - `rating` = `tc_threat_rating`

## Requirements

- A valid Recorded Future API token with access to the Fusion files endpoint for the PAD feed.
- A configured ThreatConnect Organization/owner that allows batch creation of `Host` indicators.
- The PAD feed (`new_domains_ctl.json.gz`) must be available to download.

## Local helpers (optional)

These scripts operate on the same example PAD `.gz` file used for development/testing.

### `count_recent_days.py`

Streams `example/Potentially Abused Domains (1).gz` and writes per-day record counts for the last N days.

Example:

```sh
python count_recent_days.py --days 30 --verbose
```

### `sample_pad_file.py`

Samples the first N lines from `example/Potentially Abused Domains (1).gz` into a plain-text file.

Example:

```sh
python sample_pad_file.py --num-lines 1000
```

