# Known Tor Infrastructure (Recorded Future)

Organization Job App for ThreatConnect (TcEx 4) that downloads Tor IP data from **Recorded Future Fusion** and creates **Address** indicators in batch.

## Data source

- **API**: Fusion Files `GET` with URL-encoded path (see [Recorded Future Fusion API](https://docs.recordedfuture.com/)).
- **File path**: `/public/policy/tor_ips.json` (configured in code as `TOR_FUSION_FILE_PATH` in `app.py`).
- **Headers**: `X-RFToken` (from app input `rf_token`), `Accept: application/octet-stream`.

## Inputs

| Name | Description |
|------|-------------|
| **ThreatConnect Owner** | Destination owner for new indicators |
| **Recorded Future API Token** | Token for `X-RFToken` (use Keychain or TEXT in production) |
| **Rating** / **Confidence** | Passed to batch Address indicators |

## Local run

1. Install dependencies: `tcex deps` (requires a `deps` directory).
2. Configure **ThreatConnect** standard inputs via environment variables or `.env` (see [Building Apps: Run](https://threatconnect.readme.io/docs/building-apps-tcex-run)).
3. Put app-specific values in **`app_inputs.json`** (default for `tcex run`), or use `tcex run --config-json <file>`. Keys must match `install.json` params.
4. Run: `tcex run`

Do **not** commit real `rf_token` values; `app_inputs.json` is gitignored in this template.

## Tags

Each indicator is tagged `Tor Node`, plus optional `flag:<flags>` and `name:<relay name>` (tag values truncated for length safety).

## Release notes

### 1.0.0

- Initial release: Fusion `tor_ips.json` ingest via batch Address API.
