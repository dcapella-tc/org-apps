## Release notes

### 1.0.0

# Weaponized Domains (Recorded Future)

Organization Job App for ThreatConnect (TcEx 4) that downloads weaponized domains from **Recorded Future Fusion** and creates **Host** indicators in batch.

## Data source

- **API**: Fusion Files `GET` with URL-encoded path.
- **File path**: `/public/prevent/weaponized_domains.json`.
- **Headers**: `X-RFToken` (from app input `rf_token`), `Accept: application/octet-stream`.

RF to ThreatConnect field mapping lives in `mapping.json` (loaded at runtime).

## Inputs

| Name | Description |
|------|-------------|
| **ThreatConnect Owner** | Destination owner for new indicators |
| **Recorded Future API Token** | Token for `X-RFToken` (use Keychain or TEXT in production) |
| **Rating** / **Confidence** | Passed to batch Host indicators |

## Local run

1. Install dependencies: `tcex deps` (requires a `deps` directory).
2. Configure ThreatConnect standard inputs via environment variables or `.env`.
3. Put app-specific values in `app_inputs.json` (gitignored).
4. Run: `tcex run`

- Initial release: Fusion `weaponized_domains.json` ingest via batch Host API.
