# Indicator Auto Enrichment

# Release Notes

### 1.0.0

* Initial release: TQL-select indicators and enrich them with VirusTotal V3 in batches of 500


# Description

Organization Job App that queries indicators with TQL (`GET /v3/indicators`)
and batch-enriches them via VirusTotal V3 (`POST /v3/indicators/enrich`).

### Inputs

  **TQL** *(String)*
  TQL query used to select indicators to enrich via VirusTotal V3.

### Local run

1. Install dependencies: `tcex deps`.
2. Put ThreatConnect credentials in `.env`.
3. Set the TQL query in `app_inputs.json`.
4. Run: `tcex run`
