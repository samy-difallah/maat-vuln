# Signals and identifiers

Maat resolves three signals for each vulnerability: KEV, EPSS and CVSS. They are resolved once per vulnerability, then shared by every finding of that vulnerability, whatever its component.

## KEV

The [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) of CISA lists vulnerabilities with reliable evidence of exploitation in the wild. Maat downloads the whole catalog into each snapshot and keeps, per vulnerability:

| Field | Meaning |
|---|---|
| `in_kev` | whether the vulnerability is in the catalog |
| `date_added` | when CISA added it |
| `due_date` | the remediation deadline CISA set for US federal agencies |
| `known_ransomware_campaign_use` | whether CISA knows of its use in ransomware campaigns |

The last three fields are only present for a vulnerability in KEV. The ransomware field is displayed but not used by the default policy.

## EPSS

The [Exploit Prediction Scoring System](https://www.first.org/epss/) of FIRST estimates, every day, the probability that each CVE will be exploited in the next 30 days. Maat downloads the full daily score file into each snapshot and keeps:

| Field | Meaning |
|---|---|
| `probability` | the probability of exploitation in the next 30 days, from 0 to 1 |
| `percentile` | the share of scored CVEs with a lower or equal probability |
| `model_version` | the EPSS model that computed the score |
| `score_date` | the day of the score |

The policy compares the probability only (see [Probability, not percentile](policy.md#probability-not-percentile)).

## CVSS

CVSS measures the severity of a vulnerability, not its likelihood of exploitation, which is why Maat only uses it as a secondary signal. Its values come from two places, in this order:

1. **The input**: CVSS values supplied by a scanner or a native document. When several findings of the same vulnerability carry CVSS values, all of them are combined.
2. **[CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/)**: when no finding of a vulnerability carries CVSS, Maat looks it up. It reads both the CVE record (metrics from the CNA and from ADPs such as CISA) and the NVD record, and keeps every value of both, exact duplicates once. Results are cached in the snapshot.

Each value records its `version`, `base_score`, `vector` (when known) and `source`: `input` or `vulnerability-lookup`.

A vulnerability can have several CVSS values. The policy uses one of them, the **selected** value:

1. The most recent CVSS version: 4.0, then 3.1, then 3.0, then 2.0.
2. Within that version, the highest base score.
3. Among equal scores, the first value seen.

All values stay in the report. When the selected value is CVSS 2.0, the decision gets the `cvss_legacy` flag.

## Absent or null

In the JSON report, the `signals` object distinguishes two cases:

- **`null`**: Maat looked the signal up and found nothing. `epss: null` means the CVE has no EPSS score; `cvss: null` means it has no CVSS anywhere.
- **Absent**: Maat could not compute the signal. All three are absent for an ID that is not a CVE, since no feed can be queried; `cvss` is absent when its lookup failed.

## Identifiers

### Pivot ID

KEV and EPSS are keyed by CVE ID, so Maat makes the CVE the pivot of each finding:

- When the finding's ID is a CVE, it is the pivot.
- Otherwise, when exactly one of its aliases is a CVE, that alias becomes the pivot.
- Otherwise, the finding's own ID stays the pivot, and the finding gets no signal: it is `unscored`, with the `unresolved_id` flag. It is kept, not dropped.

The pivot becomes the decision's ID, and every other ID (GHSA, OSV, distribution advisories…) goes to `aliases`. IDs are uppercased, and an ID that starts with `CVE-` but is not a well-formed CVE ID is rejected.

### Advisories covering several CVEs

Some advisories cover several vulnerabilities: a GHSA or a distribution advisory can list several CVE aliases. Such a finding is split into one finding per CVE, so that each CVE keeps its own KEV and EPSS signals instead of hiding behind one of them. Each part keeps the other IDs as aliases, the component and the sources, but no CVSS value, since nothing tells which CVE the advisory's score belongs to. CVSS is then looked up per CVE.

### Findings and components

A decision belongs to a finding, that is a vulnerability in a component, not to a vulnerability alone: the same CVE in two packages gives two decisions, with the same signals. The component is identified by its [package URL](https://github.com/package-url/purl-spec) when known, otherwise by its CycloneDX `bom-ref`, otherwise by its name and version. Findings with the same vulnerability and component are merged, as described in [Inputs](../guides/inputs.md#merging).
