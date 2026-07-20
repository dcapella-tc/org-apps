# AlienVault OTX Ingress (TcEx Batch)

# Release Notes

### 1.0.0 (2021-04-22)

* Initial Release


# Description

Organization Job App that fetches subscribed pulses from AlienVault OTX, saves
inspection JSON/CSV under the ThreatConnect output path, and (later) can feed
ThreatConnect batch ingestion.

### Inputs

  **ThreatConnect Owner** *(Choice)*
  The destination Owner in the ThreatConnect Platform.

  **OTX API Key** *(String / Keychain)*
  AlienVault OTX API key (`X-OTX-API-KEY`).

  **Last Modified** *(String, optional)*
  ISO-8601 datetime for `modified_since`. Empty uses the last 24 hours.

### Local run

1. Install dependencies: `tcex deps`.
2. Put ThreatConnect credentials in `.env` (same as other org apps), including:
   - `tc_api_path`, `tc_api_access_id`, `tc_api_secret_key`
   - `otx_api_key` — used when the app input is empty (do not commit real keys)
3. Keep app-specific non-secret values in `app_inputs.json` (`tc_owner`, `last_modified`).
   Leave `otx_api_key` out of committed `app_inputs.json` so local runs resolve it from `.env`.
4. Run: `tcex run`
