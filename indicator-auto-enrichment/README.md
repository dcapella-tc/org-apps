# Indicator Auto Enrichment

# Release Notes

### 1.1.0

* Append `vtLastUpdated is null` to the TQL query unless the query already references `vtLastUpdated`
* Treat a VirusTotal response of "No enrichment data found" as success so later batches still run

### 1.0.0

* Initial release: TQL-select indicators and enrich them with VirusTotal V3 in batches of 500

# Description

Organization Job App that queries indicators with TQL (`GET /v3/indicators`)
and batch-enriches them via VirusTotal V3 (`POST /v3/indicators/enrich`).

Unless the supplied TQL already mentions `vtLastUpdated`, the query is limited to indicators VirusTotal has not yet updated. Indicators with no VirusTotal data are logged and skipped; they do not fail the job.

### Inputs

  **TQL** *(String)*
  TQL query used to select indicators to enrich via VirusTotal V3.
