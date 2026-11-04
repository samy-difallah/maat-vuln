# Changelog

All notable changes to this project are documented in this file.

## 0.1.2 - 2026-11-04

### Refactoring

- **policy**: Name priorities CRITICAL to LOW, with P1-P4 as indicators (#30); this changes the JSON output: `priority` values and `summary` keys are now `CRITICAL`, `HIGH`, `MEDIUM` and `LOW` instead of `P1` to `P4`, and `schema_version` is `0.2.0`

### Documentation

- **readme**: Replace the title with a centered Maat logo and add badges (#29)
- **readme**: Describe v0.1 verdicts as CRITICAL to LOW in the roadmap (#31)

## 0.1.1 - 2026-11-03

### Bug fixes

- **cli**: Drop table borders and colour rank output by priority (#17)
- **cli**: Lay out snapshot show as feed blocks (#18)
- **cli**: Show progress and feed versions on snapshot fetch (#19)
- **cli**: Lay out explain output as aligned blocks (#20)
- **cli**: Keep rank table readable on narrow terminals (#21)
- **cli**: Make rank and explain output consistent and reject malformed CVE IDs (#23)
- **snapshot**: Skip damaged snapshots when picking the latest one (#25)

### Performance

- **feeds**: Validate only the asked rows when reading EPSS scores (#24)

### Refactoring

- **cli**: Move each command to its own module (#22)

### Documentation

- **readme**: Add the Maat feather logo (#26)

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
