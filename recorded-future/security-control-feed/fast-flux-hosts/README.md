## Release notes

### 1.0.1
- Removed testing blocks

### 1.0.0 (2026-04-03)

- Initial release: ingest Fast Flux host IPs from Recorded Future Fusion into ThreatConnect.
- Creates **Address** indicators via the v2 batch API in the configured owner.
- Each indicator is tagged **Fast Flux Host**; **Last Seen** is set when the source record includes `lastSeen` (epoch milliseconds in Fusion JSON), stored as a UTC ISO 8601 string for batch serialization.
- Chunking prepares up to **10,000** records per ThreatConnect batch. **Current code** exits after the first batch (`break` with a TODO in `run()`); remove that when you want full multi-batch runs for large feeds.

# Recorded Future SCF Fast Flux Hosts

Organization Job App for ThreatConnect (TcEx 4) that downloads Fast Flux IP data from **Recorded Future Fusion** and creates **Address** indicators in batch in the selected owner.

## Data source

- **API**: Fusion Files `GET` with URL-encoded path (see [Recorded Future Fusion API](https://docs.recordedfuture.com/)).
- **Base URL / path**: `RF_SCF_BASE` and `RF_SCF_PATH` in `app.py` (file path `/public/detect/fflux_ips.json`).
- **Headers**: `X-RFToken` (from app input `rf_token`), `Accept: application/octet-stream`.

## Inputs

| Name | Description |
|------|-------------|
| **ThreatConnect Owner** | The destination Owner in the ThreatConnect Platform. |
| **Recorded Future API Token** | API token for Recorded Future Fusion file download (`X-RFToken`); use Keychain or TEXT in production. |
| **Rating** | Passed to batch Address indicators. |
| **Confidence** | Passed to batch Address indicators. |
| **Logging Level** | App log verbosity (`debug`, `info`, `warning`, `error`). |

## Local run

1. Install dependencies: `tcex deps` (requires a `deps` directory).
2. Configure **ThreatConnect** standard inputs via environment variables or `.env` (see [Building Apps: Run](https://threatconnect.readme.io/docs/building-apps-tcex-run)).
3. Put app-specific values in **`app_inputs.json`** (default for `tcex run`), or use `tcex run --config-json <file>`. Keys must match `install.json` params.
4. Run: `tcex run`

## Tags and attributes

- **Tag**: `Fast Flux Host`
- **Attribute**: `Last Seen` when present in the Fusion record (`lastSeen`, epoch ms or compatible forms handled in `app.py`).
