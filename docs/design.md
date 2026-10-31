# Maat: design document

## 1. Purpose and positioning

Maat weighs vulnerabilities and returns an explained verdict. It does not discover vulnerabilities: it prioritizes findings it is given.

Prioritization from KEV + EPSS + CVSS already exists elsewhere. Maat's value is:

- **Explainability**: every priority comes from a named rule, shown by `explain`.
- **Reproducibility**: verdicts reference a dated, hashed snapshot of the feeds and a versioned policy.
- **Manufacturer (PSIRT) focus**: later VEX support, European sources and a CRA signal (see roadmap).
- **Standard quantities only**: rules and sort orders use values published by CISA and FIRST. No invented composite score.

Out of scope: SBOM generation; image/secret/IaC/license scanning; host or network scanners (Nessus, OpenVAS); web UI or multi-user server.

## 2. Key decisions

1. **Unit of prioritization: vulnerability × component.** Signals (KEV, EPSS, CVSS) are resolved once per vulnerability; the Decision belongs to the finding, because VEX and context are component-specific.
2. **Verdict: P1–P4**, sorted by EPSS probability then CVSS. No 0–100 score.
3. **Pivot identifier: CVE.** Aliases (GHSA, EUVD, GCVE, OSV…) are accepted and kept; when a CVE alias exists it becomes the pivot. Findings without a CVE are kept, without feed signals.
4. **CVSS source:** values supplied in the input first, combined across every finding of the vulnerability; otherwise looked up in CIRCL Vulnerability-Lookup and cached in the snapshot. Provenance is recorded.
5. **EPSS:** probability, percentile, model version and score date are all kept.

## 3. Data contract

General rules:

- Every top-level document carries `schema_version` (semver, starting `0.1.0`).
- Input is tolerant (unknown fields ignored, IDs normalized); output is strict.
- **Absent field = not computed; `null` = looked up, no result.** Such fields default to Pydantic's `MISSING` sentinel, which every dump omits, so the distinction survives JSON round-trips without `exclude_unset`.
- Timestamps: RFC 3339, UTC. Vulnerability IDs: uppercase.

### Finding (input)

| Field | Type | Notes |
|---|---|---|
| `id` | str | required; normalized to uppercase; replaced by the pivot after validation |
| `aliases` | list[str] | optional; normalized, deduplicated, sorted; holds every ID but the pivot |
| `component` | Component \| None | **Provisional:** optional, to allow bare IDs |
| `cvss` | list[CvssInput] | optional; CVSS supplied by the input |
| `sources` | list[Provenance] | optional; each: tool, tool_version, original_id |

Pivot: the `id` when it is a CVE; otherwise the lowest CVE alias, compared by year then number; otherwise the `id` itself.

Component: `purl` (preferred), `bom_ref`, `name`, `version`. A finding's key is `(pivot_id, component.purl or bom_ref or name@version or name or none)`, serialized in JSON as an object `{"id": ..., "component": ...}`. Findings with the same key are merged in first-seen order: aliases, CVSS values and sources are unioned, the first component is kept.

CvssInput: `version` (`4.0`, `3.1`, `3.0`, `2.0`) and `base_score` (0–10) required, `vector` optional.

Input document: `{"schema_version": ..., "findings": [...]}`. Input being tolerant, `schema_version` is optional; when present, its major version must match Maat's.

### Signals (per vulnerability, from the snapshot)

- **KEV**: `in_kev` (bool), `date_added`, `due_date`, `known_ransomware_campaign_use` (displayed only, not used by the default policy); the last three are absent when not in KEV.
- **EPSS**: `probability`, `percentile`, `model_version`, `score_date`.
- **CVSS**: `{values, selected}`, where `values` is a non-empty list of `{version, vector, base_score, source}` (`source` is `input` or `vulnerability-lookup`) and `selected` the one the policy uses. **Provisional** selection order: 4.0 > 3.1 > 3.0 > 2.0, then the highest base score within a version, then the first one seen; all values kept; selecting 2.0 adds flag `cvss_legacy`.

Signals object: `{kev, epss, cvss}`. `epss` and `cvss` are `null` when the vulnerability is not in the feed or has no CVSS; any of the three is absent when not computed (no CVE pivot, failed CVSS lookup).

### Snapshot

A directory `snapshots/<snapshot_id>/` in the user cache (platformdirs) containing the raw feed files and a `manifest.json`:

- `snapshot_id`: SHA-256 of the canonical manifest, i.e. the manifest without `snapshot_id`, serialized as JSON with sorted keys, no whitespace, UTF-8.
- `created_at`.
- `feeds`, sorted by name; per feed: `name`, `url` (the URL used), `filename` (raw file in the snapshot directory), `retrieved_at`, `sha256` of the raw file, `version`: a string map of the feed version info (KEV catalog version / date released; EPSS model version and score date).
- KEV and EPSS are stored as full feed files (not per-CVE API answers), so a snapshot is self-contained. The manifest lists only these files, so the ID never changes once the snapshot is written.
- CVSS lookups are per CVE and appended to the snapshot as they happen, in a file beside the manifest and outside the hash. Cached values are only added, never rewritten, so a report keeps reproducing against its snapshot as it grows.
- That file is `cvss.jsonl`, one JSON line per CVE looked up: `{"id", "retrieved_at", "values"}`, where `values` is a non-empty list of CVSS values (as in Signals, `source` included) or `null` for no result. When a CVE appears twice, the first line wins; a line that does not parse (interrupted write) is ignored, so the CVE is looked up again.

A snapshot is written to a temporary directory, renamed once complete. Loading one checks that its manifest still hashes to its ID. Commands reuse the latest snapshot (newest `created_at`) unless told to refresh or given a specific one.

### Decision (output, one per finding)

| Field | Notes |
|---|---|
| `finding_key` | as defined above |
| `priority` | `P1`–`P4` or `null` (unscored) |
| `rule_id` | see §4 |
| `flags` | list, see §4 |
| `explanation` | `rule` (condition text), `thresholds` (name → value), `signals` (the Signals object used) |
| `suppressed_by` | reserved for VEX support (see roadmap); absent until then |
| `policy_id`, `policy_version` | `maat-default`, `1` |
| `snapshot_id` | |

### Report (output)

`schema_version`, `generated_at`, `maat_version`, `policy` (id, version), `snapshot_id`, `decisions` (sorted, §4), `summary` (count per priority, every key always present: `{"P1", "P2", "P3", "P4", "unscored"}`).

## 4. Default policy `maat-default` v1

Rules, evaluated in order; the first match wins.

| Rule ID | Priority | Condition |
|---|---|---|
| `p1.kev` | P1 | vulnerability is in KEV |
| `p2.epss_likely` | P2 | EPSS probability ≥ 0.10 and not (CVSS < 4.0) |
| `p3.epss_capped_low_cvss` | P3 | EPSS probability ≥ 0.10 but CVSS < 4.0 |
| `p3.watch` | P3 | EPSS probability ≥ 0.01 or CVSS ≥ 7.0 |
| `p4.low` | P4 | at least one signal available |
| `none.unscored` | none | no KEV, EPSS or CVSS data |

Named constants: `EPSS_LIKELY = 0.10`, `EPSS_WATCH = 0.01`, `CVSS_HIGH = 7.0`, `CVSS_LOW_CAP = 4.0`. Changing any of them increments `policy_version`.

Principles:

- Thresholds use the raw EPSS **probability**, not the percentile (the percentile shifts with the score distribution; it is displayed only).
- **Missing data never lowers a priority; it adds a flag.** If CVSS is missing, the P2 cap does not apply.
- A signal is available when the vulnerability is in KEV, has an EPSS probability or has a CVSS value; `in_kev: false` alone is not a signal, so a CVE with nothing else is unscored.
- Flags, one per missing signal, listed in this order: `cvss_missing` (no CVSS, for any reason but a failed lookup), `cvss_lookup_failed` (CVSS absent on a CVE pivot, see §6), `epss_missing` (EPSS `null` or absent), `cvss_legacy` (selected CVSS is 2.0), `unresolved_id` (no CVE pivot), `unscored` (no priority).
- `explanation.thresholds` holds the thresholds of the matched rule, keyed by their constant names (`EPSS_LIKELY`, …).

Sort order of decisions: priority (P1 → P4, unscored last), then EPSS probability descending, then selected CVSS base score descending, then finding key ascending.

## 5. Core features

- Input: IDs as CLI arguments, one-per-line on stdin, and native JSON (§3).
- Feeds: CISA KEV, FIRST EPSS, CIRCL Vulnerability-Lookup (CVSS fallback).
- Snapshots as described in §3.
- Default policy (§4).
- Output: Rich table and JSON Report.
- CLI (names may be refined during planning):
  - `maat rank [IDS...] [--input FILE|-] [--format table|json] [--snapshot ID] [--refresh] [--concurrency N]`: ID arguments and `--input` (a JSON document, `-` for stdin) combine; with neither, stdin is read as one ID per line. When the cache holds no snapshot, one is fetched. `--concurrency` caps simultaneous CVSS lookups (§6).
  - `maat explain ID [--component PURL] [--format table|json] [--snapshot ID] [--refresh]`: rule, signal values, sources, snapshot (`json`: the Decision); snapshot options as for `rank`
  - `maat snapshot fetch` / `maat snapshot show [ID] [--format table|json]`: `fetch` prints the new snapshot ID; `show` prints the given or latest snapshot: ID, creation date, cached CVSS lookups and each feed's version, URL and hash (`json`: the manifest)
- Library entry points: `maat_vuln.aprioritize(findings, snapshot) -> Report` (async) and `maat_vuln.prioritize(findings, snapshot) -> Report` (sync facade), see §6; `maat_vuln.afetch_snapshot() -> Snapshot` and `maat_vuln.fetch_snapshot() -> Snapshot` fetch KEV and EPSS into a new snapshot.
- Generated JSON Schemas for input and Report under `schemas/`.
- Repo hygiene: Apache-2.0 `LICENSE`, `license = "Apache-2.0"` in `pyproject.toml`, CI (tests, ruff, import-linter, schema drift).

## 6. Network access

KEV and EPSS are fetched as full feed files, one request each. The only per-vulnerability requests are the CVSS lookups in Vulnerability-Lookup, for vulnerabilities none of whose findings carries CVSS in the input: that path must stay fast on inputs with hundreds of vulnerabilities.

- **Async core, sync facade.** Feed clients use `httpx.AsyncClient`. `aprioritize()` is the async entry point; `prioritize()` runs it with `asyncio.run()`. When an event loop is already running, `prioritize()` raises a clear error pointing to `aprioritize()` instead of failing obscurely.
- **One shared client** per run, so connections are reused, with explicit connect and read timeouts.
- **Bounded concurrency**: a semaphore caps simultaneous requests to one service. Default: 8, configurable from the library and the CLI.
- **Retries**: exponential backoff with jitter on transport errors, HTTP 429 and 5xx; honor `Retry-After`; give up after a bounded number of attempts without failing the whole run. A failed lookup is not a `null` (no result): the CVSS field stays absent, the finding gets the `cvss_lookup_failed` flag, and the failure is not cached in the snapshot, so a later run retries it.
- **Identification**: every request sends `User-Agent: maat-vuln/<version>`.
- **Cache first**: values already in the snapshot are never requested again.
- **Bulk access first**: before implementing per-CVE lookups, check whether Vulnerability-Lookup offers a batch endpoint or downloadable dumps; prefer them when they exist. It does: CVSS is looked up through its bulk endpoint (`POST /api/vulnerability/bulk`, at most 100 IDs per request), reading for each CVE both its CVE record (`CVE-…`: CNA and ADP metrics) and its NVD record (`fkie_cve-…`), so 50 CVEs per request. Every value of both records is kept, exact duplicates once; a failed request fails the lookup of its whole batch.
- The CLI stays synchronous and calls the sync facade.

## 7. Roadmap

Each milestone `v0.N` is the `0.N.x` release series: its features ship together in `0.N.0`, and later `0.N.x` releases only carry fixes.

Short term (committed):

- **v0.1** Reproducible core: the core features of §5.
- **v0.2** SCA inputs: adapter architecture (entry points) with auto-detection; CycloneDX (incl. VDR, which covers Dependency-Track exports), Trivy, Grype, OSV-Scanner; multi-source merge with provenance. Scanner severities ignored.
- **v0.3** Outputs and CI: SARIF, Markdown, enriched CycloneDX; `--fail-on P1|P2…`; GitHub Action.

Medium term (planned, adjustable):

- **v0.4** VEX: CycloneDX VEX, OpenVEX, CSAF VEX, through `suppressed_by`.
- **v0.5** Policy as code: YAML policies, `policy validate` / `policy test`, SSVC example policy.

Horizon (direction only, unversioned): offline bundles, `replay` / `diff`; European sources (EUVD, GCVE); context file (exposure, criticality); CRA notification signal; Dependency-Track (FPF) and Dependency-Check adapters; finer ranking formulas and graphical outputs once the tool is mature.
