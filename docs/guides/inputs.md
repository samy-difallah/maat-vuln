# Inputs

`maat rank` takes vulnerabilities in three ways, which can be combined in one run:

- IDs as arguments.
- IDs on stdin, one per line, when neither arguments nor `--input` are given.
- JSON documents with `--input FILE`, repeatable, `-` for stdin (at most once): Maat's native format, described below, or the output of an [SCA tool](sca-tools.md).

```sh
maat rank CVE-2021-44228 GHSA-jfh8-c2jp-5v3q
maat rank < ids.txt
maat rank --input findings.json CVE-2023-4863
cat findings.json | maat rank --input -
```

## IDs

Any vulnerability ID is accepted: CVE, GHSA, OSV, distribution advisories, internal IDs. IDs are uppercased. An ID that starts with `CVE-` but is not a well-formed CVE ID is an error.

A bare ID has no component and no CVSS: its CVSS is looked up when it is a CVE. A GHSA or other non-CVE ID given alone has no CVE alias, so it is `unscored`. To link it to its CVE, use a JSON document with `aliases`.

## Native JSON document

The native document lists findings: a vulnerability, optionally in a component, with what is known about it.

```json
{
  "schema_version": "0.4.0",
  "findings": [
    {
      "id": "CVE-2023-4863"
    },
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "component": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
      "cvss": [
        {"version": "3.1", "base_score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
      ],
      "sources": [{"tool": "manual-review", "original_id": "GHSA-jfh8-c2jp-5v3q"}]
    },
    {
      "id": "ACME-SA-2026-001",
      "aliases": ["CVE-2021-45046", "CVE-2021-44832"],
      "component": {"name": "acme-gateway", "version": "4.2.0"}
    }
  ]
}
```

| Field | Required | Content |
|---|---|---|
| `schema_version` | no | when present, its major version must match the one Maat writes |
| `findings` | yes | the list of findings |
| `findings[].id` | yes | the vulnerability ID |
| `findings[].aliases` | no | other IDs of the same vulnerability, such as its CVE |
| `findings[].component` | no | `purl`, `bom_ref`, `name` and `version`, all optional |
| `findings[].cvss` | no | CVSS values: `version` (`4.0`, `3.1`, `3.0` or `2.0`) and `base_score` (0 to 10) required, `vector` optional |
| `findings[].sources` | no | who reported the finding: `tool`, `tool_version` and `original_id`, all optional |

The input is tolerant: unknown fields are ignored, so a document written for a later version of Maat still reads. The JSON Schema of this format is [`schemas/input.schema.json`](https://github.com/samy-difallah/maat-vuln/blob/main/schemas/input.schema.json).

How IDs and aliases become a CVE pivot, and how an advisory covering several CVEs is split, is described in [Signals and identifiers](../concepts/signals.md#identifiers). In the example above, `ACME-SA-2026-001` becomes two findings, `CVE-2021-45046` and `CVE-2021-44832`, both in `acme-gateway@4.2.0`.

## Components

A decision belongs to a vulnerability in a component. The component is identified by the first of these that is known:

1. `purl`, the [package URL](https://github.com/package-url/purl-spec), preferred since every tool can write it the same way.
2. `bom_ref`, the CycloneDX reference of the component.
3. `name@version`.
4. `name` alone.

A finding without a component is a vulnerability on its own, as with bare IDs.

## Merging

Findings with the same pivot ID and component key are merged into one decision, in the order they were read:

- Aliases, CVSS values and sources are combined.
- The first component is kept.

This is what lets several scanners, or a scanner and a hand-written document, be ranked together: each decision lists in `sources` every tool that reported it.

CVSS values supplied for a vulnerability apply to all its findings: when any finding of a CVE carries CVSS, no lookup is made for that CVE.
