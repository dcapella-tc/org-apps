# Publish Automation

## Release Notes

### 1.0.0

-   Copy a group into one or more owners using a reproducible xid.

# Category

-   Unsupported

# Description

Copy a ThreatConnect group into one or more owners.

# Inputs

-   **request_json** _(String)_: Security-export JSON. Includes `owners`, include flags (`includeTags`, `includeAttributes`, `includeAssociatedIndicators`, `includeAssociatedGroups`), `excludedSecurityLabels`, optional `updateIfExists` (defaults to false), and `custom.group_id`.

# Outputs

-   **publish.result** _(String)_: JSON list of `{owner, xid, status}`. Status is `existing` or `published`.
