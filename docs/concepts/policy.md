# Priorities and policy

A policy turns the signals of a vulnerability into a priority. Maat ships one policy, `maat-default`, at version 1. Every decision records the policy ID and version it was made with, and any change to a threshold increments the version.

## Priorities

There are four priorities, each with a P1–P4 equivalent shown in the table and in rule IDs:

| Priority | Indicator | Meaning |
|---|---|---|
| `CRITICAL` | P1 | known to be exploited in the wild |
| `HIGH` | P2 | likely to be exploited soon |
| `MEDIUM` | P3 | worth watching |
| `LOW` | P4 | some data, nothing alarming |

A vulnerability Maat has no data on at all gets no priority: it is `unscored` (`null` in JSON). It is listed last, never dropped.

Maat gives no 0–100 score. Within a priority, decisions are ordered by the values CISA and FIRST publish, as [described below](#sort-order).

## Rules

The rules of `maat-default` v1 are evaluated in order, and the first one that matches wins:

| Rule ID | Priority | Condition |
|---|---|---|
| `p1.kev` | `CRITICAL` | the vulnerability is in KEV |
| `p2.epss_likely` | `HIGH` | EPSS probability ≥ `EPSS_LIKELY` and not CVSS < `CVSS_LOW_CAP` |
| `p3.epss_capped_low_cvss` | `MEDIUM` | EPSS probability ≥ `EPSS_LIKELY` but CVSS < `CVSS_LOW_CAP` |
| `p3.watch` | `MEDIUM` | EPSS probability ≥ `EPSS_WATCH` or CVSS ≥ `CVSS_HIGH` |
| `p4.low` | `LOW` | at least one signal available |
| `none.unscored` | none | no KEV, EPSS or CVSS data |

With these thresholds:

| Constant | Value | Compared with |
|---|---|---|
| `EPSS_LIKELY` | 0.10 | EPSS probability |
| `EPSS_WATCH` | 0.01 | EPSS probability |
| `CVSS_HIGH` | 7.0 | selected CVSS base score |
| `CVSS_LOW_CAP` | 4.0 | selected CVSS base score |

In words:

- **`p1.kev`**: a vulnerability in KEV is being exploited now. Nothing else matters: it is `CRITICAL` whatever its EPSS or CVSS.
- **`p2.epss_likely`**: an EPSS probability of 10% or more over the next 30 days is high, unless CVSS says the impact is low.
- **`p3.epss_capped_low_cvss`**: a likely exploit of a low-severity vulnerability (CVSS below 4.0) does limited damage, so it is capped at `MEDIUM`.
- **`p3.watch`**: an EPSS probability of 1% or more, or a CVSS of 7.0 or more, deserves a look but no emergency.
- **`p4.low`**: everything else that has at least one signal.
- **`none.unscored`**: no signal at all, typically an ID that is not a CVE (see [Signals and identifiers](signals.md#identifiers)).

`maat explain` and the JSON report give, for each decision, the rule ID, its condition as text (`explanation.rule`), the thresholds the rule compared (`explanation.thresholds`, keyed by constant name) and the signal values used (`explanation.signals`).

## Probability, not percentile

Rules compare the raw EPSS **probability**. The percentile is shown but never used: it ranks a vulnerability among all others, so it moves whenever the distribution of scores moves, even when the vulnerability's own probability does not.

## Missing data never lowers a priority

A signal Maat could not get never pushes a vulnerability down. In particular, when CVSS is missing, the `HIGH` cap of `p3.epss_capped_low_cvss` does not apply: a vulnerability with an EPSS probability of 0.10 or more and no CVSS is `HIGH`.

A vulnerability has a signal when it is in KEV, has an EPSS probability or has a CVSS value. Not being in KEV is not a signal on its own: a CVE that is in no feed and has no CVSS is `unscored`.

## Flags

Each missing piece of data adds a flag to the decision, in this order:

| Flag | Meaning |
|---|---|
| `cvss_missing` | no CVSS value: none in the input, and none found in Vulnerability-Lookup (or the ID is not a CVE, so no lookup was made) |
| `cvss_lookup_failed` | the CVSS lookup failed (network error, server error); the next run tries again |
| `epss_missing` | the vulnerability has no EPSS score, or is not a CVE |
| `cvss_legacy` | the only CVSS available is version 2.0, less reliable than later versions |
| `unresolved_id` | the ID is not a CVE and has no CVE alias, so no feed could be queried |
| `unscored` | the decision has no priority |

A flag tells you how much to trust a verdict. A `LOW` with `epss_missing` and `cvss_lookup_failed` says little; a `LOW` without flags says that the data is there and is reassuring.

## Sort order

Decisions are sorted by:

1. Priority, `CRITICAL` first, unscored last.
2. EPSS probability, highest first.
3. Selected CVSS base score, highest first.
4. Finding key (vulnerability ID, then component), in alphabetical order, so the order is stable.

`maat rank --top N` keeps the first N decisions in this order.
