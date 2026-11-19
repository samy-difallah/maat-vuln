# Maat

Maat ranks vulnerabilities by how likely they are to be exploited. It is a Python library with a thin command line on top. You give it the vulnerabilities you found, as bare IDs or as the JSON output of an SCA tool, and it returns a verdict for each one: `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`.

Verdicts rest on two public sources of exploitation data:

- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), the catalog of vulnerabilities known to be exploited in the wild.
- [FIRST EPSS](https://www.first.org/epss/), the daily probability that a vulnerability will be exploited in the next 30 days.

CVSS comes in as a secondary signal. It is taken from the input when the scanner supplies it, and otherwise looked up in [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/).

```console
$ maat rank CVE-2021-44228 CVE-2023-4863 CVE-2020-1747 CVE-2019-10744
Priority       ID              KEV     EPSS   Pctl  CVSS  Rule      Flags
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL (P1)  CVE-2021-44228  yes  0.99999  1.000  10.0  p1.kev    -
CRITICAL (P1)  CVE-2023-4863   yes  0.99979  1.000   8.8  p1.kev    -
MEDIUM (P3)    CVE-2020-1747   no   0.05442  0.929   9.8  p3.watch  -
MEDIUM (P3)    CVE-2019-10744  no   0.05006  0.924   9.1  p3.watch  -
```

## What sets it apart

- **Explained**: every verdict comes from a named rule of a published [policy](concepts/policy.md). `maat explain` shows the rule, its thresholds and every signal value it used.
- **Reproducible**: the feeds are stored in a dated, hashed [snapshot](concepts/snapshots.md), and every report names the snapshot and the policy version it was computed with. Ranking again against the same snapshot gives the same verdicts.
- **Standard quantities only**: rules compare the values that CISA and FIRST publish. There is no composite 0–100 score to interpret.
- **Scanner-agnostic**: CycloneDX (VDR and Dependency-Track exports included), Trivy, Grype and OSV-Scanner outputs are read as they are, and several of them can be combined in one run.

Maat does not find vulnerabilities: it prioritizes the ones a scanner or a security team gives it.

## Where to go next

- [Getting started](getting-started.md): install Maat and rank your first vulnerabilities.
- [Priorities and policy](concepts/policy.md): how a verdict is reached.
- [SCA tools](guides/sca-tools.md): rank the output of your scanner.
- [Python library](guides/library.md): use Maat from your own code.
- [Command line](reference/cli.md): every command and option.
