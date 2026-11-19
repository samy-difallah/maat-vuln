<h1 align="center"><img src="https://raw.githubusercontent.com/samy-difallah/maat-vuln/main/docs/assets/maat.svg" alt="Maat" height="128"></h1>

<p align="center"><a href="https://pypi.org/project/maat-vuln/"><img src="https://img.shields.io/pypi/v/maat-vuln" alt="PyPI version"></a> <a href="https://pypi.org/project/maat-vuln/"><img src="https://img.shields.io/pypi/pyversions/maat-vuln" alt="Python versions"></a> <a href="https://maat-vuln.readthedocs.io/"><img src="https://img.shields.io/readthedocs/maat-vuln" alt="Documentation status"></a> <a href="https://github.com/samy-difallah/maat-vuln/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://github.com/samy-difallah/maat-vuln/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a> <a href="https://github.com/samy-difallah/maat-vuln/blob/main/LICENSE"><img src="https://img.shields.io/github/license/samy-difallah/maat-vuln" alt="License"></a></p>

Exploitation-driven vulnerability prioritization, as a Python library with a thin CLI on top. Maat ranks vulnerabilities with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/), with CVSS as a secondary signal. Every verdict comes from a named rule, is explained, and is tied to a dated, hashed snapshot of the feeds.

The [documentation](https://maat-vuln.readthedocs.io/) covers every concept, command and option in detail.

## Installation

Maat requires Python 3.12 or later.

```sh
pip install maat-vuln
```

## Usage

Rank vulnerabilities, `CRITICAL` first:

```sh
maat rank CVE-2021-44228 CVE-2023-4863
maat rank < ids.txt
maat rank --input findings.json --format json
maat rank --input trivy.json --input osv-scanner.json
maat rank --input trivy.json --min-priority HIGH --top 20
```

IDs are given as arguments, one per line on stdin, or as a JSON document with `--input` (`-` for stdin). Aliases such as GHSA IDs are accepted; when a CVE alias exists, it becomes the pivot ID. A JSON document can also carry the component and CVSS values supplied by a scanner:

```json
{
  "findings": [
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "component": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
      "cvss": [{"version": "3.1", "base_score": 10.0}]
    }
  ]
}
```

`--input` also reads the JSON output of SCA tools: CycloneDX BOMs and VDRs (including Dependency-Track exports), Trivy, Grype (`-o json`) and OSV-Scanner. The format is detected from the document's structure. `--input` can be repeated to combine documents in any formats (`-` at most once): findings of the same vulnerability and component are merged, and each decision lists the tools that reported it. CVSS values reported by the tools are used; their severity labels are ignored. The [examples](https://github.com/samy-difallah/maat-vuln/tree/main/docs/examples) hold real outputs of each tool to try it on. `maat formats` lists the formats installed.

`--min-priority CRITICAL|HIGH|MEDIUM|LOW` keeps the decisions of that priority or above, and `--top N` the first N of them; the summary still counts every decision. `-q/--quiet` prints nothing, so only the exit code tells how the run went, and `-v/--verbose` prints every processing step on stderr.

Explain the priority of one vulnerability, with the rule that matched and every signal used:

```sh
maat explain CVE-2021-44228
```

Feeds are stored in snapshots in the user cache, or in the directory given by `--cache-dir DIR`. The first command fetches one; later commands reuse the latest one unless given `--refresh` or `--snapshot ID`, so a report can be reproduced against the snapshot it names. A warning tells when the latest snapshot is more than 24 hours old; `--max-age HOURS` fetches a new one when the latest is older than that:

```sh
maat snapshot fetch
maat snapshot show
maat snapshot list
maat snapshot prune --keep 5
maat snapshot rm ID
```

Defaults can be set in a `maat.toml` file, read from the current directory or given with `--config FILE`, with the keys `cache_dir`, `concurrency`, `max_age`, `stale_after` (the age of the warning, in hours), `format` and `min_priority`. Every key that has a flag can also be set as a `MAAT_*` environment variable (`MAAT_CACHE_DIR`, `MAAT_FORMAT`…). A flag wins over its variable, which wins over the file:

```toml
cache_dir = ".maat-cache"
max_age = 12
min_priority = "HIGH"
```

`maat -V` prints the version. Every command accepts `--help`. JSON output follows the schemas in [schemas/](https://github.com/samy-difallah/maat-vuln/tree/main/schemas).

### Python library

```python
from maat_vuln import fetch_snapshot, prioritize
from maat_vuln.models import Finding

snapshot = fetch_snapshot()
report = prioritize([Finding(id="CVE-2021-44228")], snapshot)
for decision in report.decisions:
    print(decision.priority, decision.finding_key.id, decision.rule_id)
```

`aprioritize` and `afetch_snapshot` are the async versions. `load_findings(document)` turns a parsed JSON document in any supported format into findings.

## Default policy

The `maat-default` v1 policy evaluates these rules in order; the first match wins:

| Rule | Priority | Condition |
|---|---|---|
| `p1.kev` | CRITICAL (P1) | in KEV |
| `p2.epss_likely` | HIGH (P2) | EPSS probability ≥ 0.10 and not CVSS < 4.0 |
| `p3.epss_capped_low_cvss` | MEDIUM (P3) | EPSS probability ≥ 0.10 but CVSS < 4.0 |
| `p3.watch` | MEDIUM (P3) | EPSS probability ≥ 0.01 or CVSS ≥ 7.0 |
| `p4.low` | LOW (P4) | at least one signal available |
| `none.unscored` | none | no KEV, EPSS or CVSS data |

Missing data never lowers a priority: it adds a flag such as `cvss_missing` or `epss_missing`. Within a priority, decisions are sorted by EPSS probability, then CVSS base score. CVSS comes from the input first, otherwise from [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/). The [design document](https://github.com/samy-difallah/maat-vuln/blob/main/docs/design.md) details the data contract and the policy.

## Roadmap

- **v0.1** (released): reproducible core. CRITICAL to LOW verdicts from KEV, EPSS and CVSS with an explanation for each, dated and hashed feed snapshots, table and JSON output, CLI and Python library.
- **v0.2** (released): SCA inputs. CycloneDX (including VDR), Trivy, Grype and OSV-Scanner, with multi-source merge and provenance.
- **v0.3** (released): command line. Version, quiet and verbose modes, a cache directory, a config file and environment variables, snapshot freshness checks and housekeeping, a list of input formats, and filters on `rank` output.
- **v0.4** (planned): VEX. CycloneDX VEX, OpenVEX and CSAF VEX statements to suppress findings that do not affect a product.
- **Later**: outputs and CI (v0.5) and policies as code (v0.6).

## Contributing

See [CONTRIBUTING.md](https://github.com/samy-difallah/maat-vuln/blob/main/CONTRIBUTING.md).

## License

[Apache-2.0](https://github.com/samy-difallah/maat-vuln/blob/main/LICENSE).
