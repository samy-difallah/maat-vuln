# JSON output

`maat rank --format json` prints a report, and `maat explain --format json` prints one decision. Both follow the JSON Schema in [`schemas/report.schema.json`](https://github.com/samy-difallah/maat-vuln/blob/main/schemas/report.schema.json), generated from the same Pydantic models as the [Python API](api.md).

General rules:

- **Absent and `null` differ**: an absent field was not computed; `null` means it was computed and there is no value. For instance, `epss: null` means the CVE has no EPSS score, while no `epss` at all means EPSS could not be queried (see [Signals and identifiers](../concepts/signals.md#absent-or-null)).
- Timestamps are RFC 3339, in UTC. Vulnerability IDs are uppercase.
- The output is deterministic: the same input against the same snapshot gives the same report, `generated_at` aside.
- Every report carries `schema_version`, the version of this format.

## Report

```json
{
  "schema_version": "0.4.0",
  "generated_at": "2026-11-19T20:58:30.596492Z",
  "maat_version": "0.3.2",
  "policy": {"id": "maat-default", "version": 1},
  "snapshot_id": "806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979",
  "decisions": [],
  "summary": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "unscored": 0}
}
```

| Field | Content |
|---|---|
| `schema_version` | version of this format |
| `generated_at` | when the report was made |
| `maat_version` | the Maat release that made it |
| `policy` | `id` and `version` of the policy applied |
| `snapshot_id` | the [snapshot](../concepts/snapshots.md) the signals come from |
| `decisions` | one decision per finding, in the [sort order](../concepts/policy.md#sort-order) of the policy |
| `summary` | number of decisions per priority; every key is always present, and every decision is counted, selected or not |
| `selection` | only when `--min-priority` or `--top` left decisions out: `min_priority` and `top` as given (each absent when not given), and `total`, the number of decisions before selection |

## Decision

```json
{
  "finding_key": {"id": "CVE-2023-4863", "component": null},
  "aliases": [],
  "sources": [],
  "priority": "CRITICAL",
  "rule_id": "p1.kev",
  "flags": [],
  "explanation": {
    "rule": "vulnerability is in KEV",
    "thresholds": {},
    "signals": {
      "kev": {
        "in_kev": true,
        "date_added": "2023-09-13",
        "due_date": "2023-10-04",
        "known_ransomware_campaign_use": false
      },
      "epss": {
        "probability": 0.99979,
        "percentile": 0.9998,
        "model_version": "v2026.06.15",
        "score_date": "2026-11-16"
      },
      "cvss": {
        "values": [
          {
            "version": "3.1",
            "base_score": 8.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "source": "vulnerability-lookup"
          }
        ],
        "selected": {
          "version": "3.1",
          "base_score": 8.8,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "source": "vulnerability-lookup"
        }
      }
    }
  },
  "policy_id": "maat-default",
  "policy_version": 1,
  "snapshot_id": "806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979"
}
```

| Field | Content |
|---|---|
| `finding_key` | what the decision is about: `id`, the pivot vulnerability ID, and `component`, the [component key](../guides/inputs.md#components) or `null` |
| `aliases` | the other IDs of the vulnerability, sorted |
| `sources` | the tools that reported the finding: `tool`, `tool_version`, `original_id` |
| `priority` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `null` when unscored |
| `rule_id` | the [rule](../concepts/policy.md#rules) that matched |
| `flags` | the missing signals, in the [order](../concepts/policy.md#flags) of the policy |
| `explanation.rule` | the condition of the rule, as text |
| `explanation.thresholds` | the thresholds the rule compared, keyed by constant name, such as `{"EPSS_LIKELY": 0.1}` |
| `explanation.signals` | the signals used: `kev`, `epss` and `cvss`, as described below |
| `policy_id`, `policy_version` | the policy applied |
| `snapshot_id` | the snapshot the signals come from |

## Signals

| Field | Content |
|---|---|
| `kev.in_kev` | whether the vulnerability is in KEV |
| `kev.date_added`, `kev.due_date` | dates CISA added it and set for its remediation; absent when not in KEV |
| `kev.known_ransomware_campaign_use` | whether CISA knows of its use in ransomware campaigns; absent when not in KEV |
| `epss.probability`, `epss.percentile` | EPSS probability of exploitation in the next 30 days, and its percentile |
| `epss.model_version`, `epss.score_date` | the EPSS model and the day of the score |
| `cvss.values` | every CVSS value known: `version`, `base_score`, `vector` (when known) and `source` (`input` or `vulnerability-lookup`) |
| `cvss.selected` | the value the policy used, one of `values` |

`epss` and `cvss` are `null` when the vulnerability has no EPSS score or no CVSS. `kev`, `epss` and `cvss` are absent when they could not be computed: all three for an ID that is not a CVE, `cvss` alone when its lookup failed.
