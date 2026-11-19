# SCA tools

`maat rank --input` reads the JSON output of the main software composition analysis (SCA) tools as it is, with no conversion step. Maat adds what the scanners leave out, the exploitation data, and keeps what they know: components, aliases and CVSS values.

## Supported formats

| Format | Tool output | Command |
|---|---|---|
| `cyclonedx` | CycloneDX BOM with `vulnerabilities`, VDR included: Trivy, Dependency-Track exports and other CycloneDX producers | `trivy fs --scanners vuln --format cyclonedx --output bom.json .` |
| `trivy` | Trivy JSON report | `trivy fs --scanners vuln --format json --output trivy.json .` |
| `grype` | Grype JSON report | `grype dir:. -o json --file grype.json` |
| `osv-scanner` | OSV-Scanner JSON report | `osv-scanner scan source -r --format json --output-file osv-scanner.json .` |
| `maat` | Maat's native document | see [Inputs](inputs.md#native-json-document) |

Only JSON is read: CycloneDX XML is not. `maat formats` lists the formats installed, including those added by other packages (see [Python library](library.md#adding-an-input-format)).

The [examples](../examples/README.md) hold real outputs of each tool on a small vulnerable project, to try Maat without installing any scanner.

## Format detection

Maat recognizes each format from the top-level structure of the document: `bomFormat: "CycloneDX"`, Trivy's `SchemaVersion`, Grype's `matches`, OSV-Scanner's `results`, or the native `findings`. There is no option to choose a format. A document that matches no format is an error listing the supported ones; one that matches several is an error naming them.

## What is read

For every format:

- **IDs**: the vulnerability ID reported by the tool becomes the finding's ID, and the related IDs it lists become aliases. The CVE pivot and the split of multi-CVE advisories then apply, as described in [Signals and identifiers](../concepts/signals.md#identifiers).
- **Component**: the package URL reported by the tool, otherwise its name and version.
- **CVSS**: the CVSS values reported by the tool, with their version, base score and vector. A value without a base score, a bare vector, is dropped. When no finding of a vulnerability carries CVSS, it is looked up in Vulnerability-Lookup.
- **Severity labels are ignored**: the `HIGH` or `CRITICAL` that a scanner assigns are its own judgment, often taken from CVSS alone. Maat only uses CVSS values and its own policy.
- **Provenance**: each finding gets one `sources` entry: the tool name and version as the document records them, and the vulnerability ID as the tool reported it.

## Format notes

### CycloneDX

Each vulnerability gives one finding per component it affects, found through the `affects` references. Only CVSS ratings are read (`scoreMethod` `CVSSv2`, `CVSSv3`, `CVSSv31` or `CVSSv4`); OWASP, SSVC and other ratings are ignored. The tool is the one named in the BOM's metadata, `cyclonedx` when it names none.

Grype's CycloneDX output (`-o cyclonedx-json`) names each vulnerability by its GHSA or Go ID with no CVE reference, so its findings get no KEV or EPSS signal: Log4Shell comes out as a `MEDIUM` GHSA instead of a `CRITICAL` CVE. Use Grype's native JSON (`-o json`) instead, which lists the related CVEs.

### Trivy

Vendor advisory IDs (`VendorIDs`) are not kept as aliases, since one advisory often covers several vulnerabilities.

### Grype

A match on a distribution advisory, such as an Amazon Linux `ALAS-…`, can cover several CVEs. Grype lists each CVE as a related vulnerability with its own CVSS values, so Maat splits such a match into one finding per CVE, each with its own CVSS.

### OSV-Scanner

- OSV records give CVSS as bare vectors, without base score, so no CVSS is read from them: it is looked up instead.
- When a record has no CVE among its ID and aliases, the CVEs listed in its `related` and `upstream` fields become aliases. A PyPI advisory often lists its CVE only as related.
- OSV-Scanner writes Go module versions without their `v` (`@1.6.3`), unlike the other tools; Maat puts it back in the package URL, so the same Go component merges across tools.
- The report does not record the OSV-Scanner version, so `tool_version` is empty.

## Combining several tools

`--input` can be repeated, with documents in any formats:

```sh
maat rank --input trivy.json --input grype.json --input osv-scanner.json --input findings.json
```

Findings of the same vulnerability and component are [merged](inputs.md#merging): a vulnerability reported by three tools gives one decision, whose `sources` lists all three, and whose CVSS values are combined. A vulnerability found by one tool only still gets its decision. Since Maat merges on the package URL, tools that write the same purl for the same package agree.
