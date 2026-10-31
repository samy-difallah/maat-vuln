# Maât

Exploitation-driven vulnerability prioritization, as a Python library with a thin CLI on top. Maât ranks vulnerabilities with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/), with CVSS as a secondary signal. Every verdict comes from a named rule, is explained, and is tied to a dated, hashed snapshot of the feeds.

## Installation

Maât requires Python 3.12 or later.

```sh
pip install maat-vuln
```

## Usage

Rank vulnerabilities, P1 first:

```sh
maat rank CVE-2021-44228 CVE-2023-4863
maat rank < ids.txt
maat rank --input findings.json --format json
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

Explain the priority of one vulnerability, with the rule that matched and every signal used:

```sh
maat explain CVE-2021-44228
```

Feeds are stored in snapshots in the user cache. The first command fetches one; later commands reuse the latest one unless given `--refresh` or `--snapshot ID`, so a report can be reproduced against the snapshot it names:

```sh
maat snapshot fetch
maat snapshot show
```

Every command accepts `--help`. JSON output follows the schemas in [schemas/](https://github.com/samy-difallah/maat-vuln/tree/main/schemas).

### Python library

```python
from maat_vuln import fetch_snapshot, prioritize
from maat_vuln.models import Finding

snapshot = fetch_snapshot()
report = prioritize([Finding(id="CVE-2021-44228")], snapshot)
for decision in report.decisions:
    print(decision.priority, decision.finding_key.id, decision.rule_id)
```

`aprioritize` and `afetch_snapshot` are the async versions.

## Default policy

The `maat-default` v1 policy evaluates these rules in order; the first match wins:

| Rule | Priority | Condition |
|---|---|---|
| `p1.kev` | P1 | in KEV |
| `p2.epss_likely` | P2 | EPSS probability ≥ 0.10 and not CVSS < 4.0 |
| `p3.epss_capped_low_cvss` | P3 | EPSS probability ≥ 0.10 but CVSS < 4.0 |
| `p3.watch` | P3 | EPSS probability ≥ 0.01 or CVSS ≥ 7.0 |
| `p4.low` | P4 | at least one signal available |
| `none.unscored` | none | no KEV, EPSS or CVSS data |

Missing data never lowers a priority: it adds a flag such as `cvss_missing` or `epss_missing`. Within a priority, decisions are sorted by EPSS probability, then CVSS base score. CVSS comes from the input first, otherwise from [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/). The [design document](https://github.com/samy-difallah/maat-vuln/blob/main/docs/design.md) details the data contract and the policy.

## Roadmap

- **v0.1** (released): reproducible core. P1–P4 verdicts from KEV, EPSS and CVSS with an explanation for each, dated and hashed feed snapshots, table and JSON output, CLI and Python library.
- **v0.2** (planned): SCA inputs. CycloneDX (including VDR), Trivy, Grype and OSV-Scanner, with multi-source merge and provenance.
- **v0.3** (planned): outputs and CI. SARIF, Markdown and enriched CycloneDX output, a `--fail-on` threshold and a GitHub Action.
- **Later**: VEX support (v0.4) and policies as code (v0.5).

## Contributing

See [CONTRIBUTING.md](https://github.com/samy-difallah/maat-vuln/blob/main/CONTRIBUTING.md).

## License

[Apache-2.0](https://github.com/samy-difallah/maat-vuln/blob/main/LICENSE).
