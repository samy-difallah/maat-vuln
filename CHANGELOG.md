# Changelog

All notable changes to this project are documented in this file.

## 0.1.0 - 2026-10-31

First release: the reproducible core.

### Features

- **models**: Pydantic data contract for findings, signals, decisions and reports, with uppercase IDs, a CVE pivot over aliases and merging of findings that share a vulnerability and a component
- **schemas**: JSON Schemas for the input document and the report, generated from the models
- **policy**: `maat-default` v1 policy, P1 for KEV, then P2–P4 from the EPSS probability with CVSS as a secondary signal; every decision names its rule, thresholds and flags for missing data
- **snapshot**: KEV and EPSS feeds stored in dated snapshots identified by the SHA-256 of their manifest, with CVSS lookups cached beside it
- **feeds**: CISA KEV catalog, FIRST EPSS scores and CIRCL Vulnerability-Lookup CVSS clients over one shared HTTP client with timeouts, retries and bounded concurrency
- **engine**: `prioritize` / `aprioritize` and `fetch_snapshot` / `afetch_snapshot` library entry points
- **cli**: `maat rank`, `maat explain`, `maat snapshot fetch` and `maat snapshot show`, with table and JSON output
