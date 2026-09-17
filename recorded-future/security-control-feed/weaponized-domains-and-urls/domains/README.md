# Weaponized Domains and URLs: Domains (Recorded Future)

Organization Job App for ThreatConnect (TcEx 4) that downloads weaponized domains from **Recorded Future Fusion** and creates **Host** indicators in batch.

## Data source

- **API**: Fusion Files `GET` with URL-encoded path.
- **File path**: `/public/prevent/weaponized_domains.json` (configured in `app.py` as `RF_SCF_PATH`).
- **Headers**: `X-RFToken` (from app input `rf_token`), `Accept: application/octet-stream`.

RF to ThreatConnect field mapping lives in `mapping.json` (loaded at runtime).

## Mapping

Each Fusion `results` row with a `domain` becomes a **Host** indicator:

| Fusion field | ThreatConnect |
|--------------|---------------|
| `domain` | Host summary |
| `last_seen` | Last Seen (datetime) |
| `service_provider` | Source |
| computed uuid5 of the row | UUID |
| truthy keys in `detection_strings` | tags |

Fixed tags: `Weaponized Domain`, `prevent`, `Weaponized Domains and URLs: Domains`.

## Incremental import

1. After download, SHA-256 of the Fusion file is compared to optional input `feed_hash`. If it matches, the job writes `results.tc` and exits (no UUID TQL, no batch).
2. Otherwise each row is fingerprinted. Rows whose `UUID` already exists in the owner are skipped; new or changed rows are batched.

Map the previous job `feed_hash` output into the `feed_hash` input for the next run. Leave it empty on first run.

## Inputs

| Name | Description |
|------|-------------|
| **ThreatConnect Owner** | Destination owner for new indicators |
| **Recorded Future API Token** | Token for `X-RFToken` (use Keychain or TEXT in production) |
| **Rating** / **Confidence** | Passed to batch Host indicators |
| **Feed Hash** | Optional. Leave empty on first run. Map the previous job `feed_hash` output into this input. An identical Fusion file skips UUID TQL and batch. |

## Release notes

### 1.0.0

- Initial release: Fusion `weaponized_domains.json` ingest via batch Host API.
- Incremental import: skip an unchanged Fusion file via `feed_hash`; otherwise skip records whose `UUID` attribute already exists in the owner.
