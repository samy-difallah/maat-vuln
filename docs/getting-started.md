# Getting started

## Install

Maat requires Python 3.12 or later. Install it from PyPI, preferably in a virtual environment:

```sh
pip install maat-vuln
```

This installs the `maat` command and the `maat_vuln` Python package. Check the installation with:

```console
$ maat -V
maat-vuln 0.3.0
```

## Rank vulnerabilities

Give `maat rank` the vulnerability IDs to rank:

```console
$ maat rank CVE-2021-44228 CVE-2023-4863 CVE-2019-10744 CVE-2020-1747 GHSA-xxxx-yyyy-zzzz
Priority       ID                   KEV     EPSS   Pctl  CVSS  Rule           Flags
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL (P1)  CVE-2021-44228       yes  0.99999  1.000  10.0  p1.kev         -
CRITICAL (P1)  CVE-2023-4863        yes  0.99979  1.000   8.8  p1.kev         -
MEDIUM (P3)    CVE-2020-1747        no   0.05442  0.929   9.8  p3.watch       -
MEDIUM (P3)    CVE-2019-10744       no   0.05006  0.924   9.1  p3.watch       -
unscored       GHSA-XXXX-YYYY-ZZZZ  -          -      -     -  none.unscored  cvss_missing
                                                                              epss_missing
                                                                              unresolved_id
                                                                              unscored

CRITICAL 2 · HIGH 0 · MEDIUM 2 · LOW 0 · unscored 1

snapshot 806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979
```

The first run downloads the KEV catalog and the EPSS scores into a [snapshot](concepts/snapshots.md) in your user cache; later runs reuse it. The numbers above come from one snapshot: yours will differ, since both feeds change every day.

IDs can also come from stdin, one per line:

```sh
maat rank < ids.txt
```

## Read the table

Each row is a decision:

- **Priority**: the verdict, `CRITICAL` to `LOW`, with its P1–P4 equivalent, or `unscored` when Maat has no data on the vulnerability at all.
- **ID**: the vulnerability, normalized to uppercase. A CVE alias, when known, replaces any other ID (see [Signals and identifiers](concepts/signals.md#identifiers)).
- **KEV**: whether the vulnerability is in the CISA KEV catalog.
- **EPSS** and **Pctl**: the EPSS probability of exploitation in the next 30 days, and its percentile among all scored vulnerabilities. Rules only use the probability.
- **CVSS**: the base score the policy used.
- **Rule**: the rule of the [policy](concepts/policy.md) that matched. The first rule that matches wins.
- **Flags**: the signals that were missing. Missing data never lowers a priority; it is flagged instead.

Rows are sorted by priority, then by EPSS probability, then by CVSS base score. The line below the table counts decisions per priority, and the last one names the snapshot used, so the report can be reproduced.

## Explain a verdict

`maat explain` shows how one vulnerability got its priority: the rule and its condition, every signal value and where the feeds came from.

```console
$ maat explain CVE-2023-4863
ID           CVE-2023-4863
Priority     CRITICAL (P1)

Rule         p1.kev
Condition    vulnerability is in KEV

KEV          in KEV, added 2023-09-13, due 2023-10-04, ransomware use unknown
EPSS         probability 0.99979, percentile 0.99980, model v2026.06.15, scored 2026-11-16
CVSS         8.8 v3.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (vulnerability-lookup) selected

Snapshot     806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979
Created      2026-11-16T22:35:17Z
KEV source   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, retrieved 2026-11-16T22:35:14Z
EPSS source  https://epss.empiricalsecurity.com/epss_scores-current.csv.gz, retrieved 2026-11-16T22:35:17Z
```

## Rank a scanner's output

`--input` reads a JSON document: the JSON output of CycloneDX, Trivy, Grype or OSV-Scanner, or Maat's own format. The format is detected, and `--input` can be repeated to combine several documents:

```sh
trivy fs --scanners vuln --format json --output trivy.json .
maat rank --input trivy.json
maat rank --input trivy.json --input osv-scanner.json
```

Decisions are then made per vulnerability and component: a vulnerability found in two packages gets two rows. See [SCA tools](guides/sca-tools.md) for each format.

## Keep what matters

On a large scan, keep only the decisions of a given priority or above, or the first N:

```sh
maat rank --input trivy.json --min-priority HIGH
maat rank --input trivy.json --top 20
```

The summary line still counts every decision.

## Get JSON

`--format json` prints a JSON report instead of the table, for scripts and other tools. Its fields are described in [JSON output](reference/json.md).

```sh
maat rank --input trivy.json --format json > report.json
```

## Next steps

- [Priorities and policy](concepts/policy.md) explains each rule and flag.
- [Snapshots](concepts/snapshots.md) explains how feeds are cached and refreshed.
- [Configuration](guides/configuration.md) sets defaults in a `maat.toml` file.
