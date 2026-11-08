# Examples

Real outputs of supported SCA tools, and a native findings document, to try `maat rank` without installing any scanner.

## Scanned project

[project/](project) is a deliberately vulnerable project: a Gradle lockfile with 11 old Maven packages (Log4j, Struts, Spring, XStream…), a Go module with 5 old dependencies and a Poetry lockfile with 2 old Python packages (aiohttp, Pillow). It only holds lockfiles, so every tool sees the same packages without resolving anything.

## Files

| File | Format | Command |
|---|---|---|
| [trivy.json](inputs/trivy.json) | `trivy` | `trivy fs --scanners vuln --format json --output inputs/trivy.json project` |
| [trivy-cyclonedx.json](inputs/trivy-cyclonedx.json) | `cyclonedx` | `trivy fs --scanners vuln --format cyclonedx --output inputs/trivy-cyclonedx.json project` |
| [grype.json](inputs/grype.json) | `grype` | `grype dir:project -o json --file inputs/grype.json` |
| [grype-cyclonedx.json](inputs/grype-cyclonedx.json) | `cyclonedx` | `grype dir:project -o cyclonedx-json --file inputs/grype-cyclonedx.json` |
| [osv-scanner.json](inputs/osv-scanner.json) | `osv-scanner` | `osv-scanner scan source -r --format json --output-file inputs/osv-scanner.json project` |
| [findings.json](inputs/findings.json) | `maat` | written by hand |

The scans ran on 2026-11-07 with Trivy 0.76.2, Grype 0.121.2 and OSV-Scanner 2.7.0, from this directory. The tool outputs are unchanged, except local absolute paths, replaced by relative ones (`project/…`) or `~`. Their vulnerability databases change daily: a new scan of the same project gives different results.

Grype's CycloneDX output names vulnerabilities by their GHSA or Go IDs without any CVE, so Maat finds no KEV or EPSS signal for them: Log4Shell comes out as `GHSA-JFH8-C2JP-5V3Q`, `MEDIUM` from its CVSS alone instead of `CRITICAL` from KEV. Use `grype -o json` instead.

[findings.json](inputs/findings.json) is a native document as a product security team could write it: a bare CVE ID, a GHSA ID with its CVE alias and CVSS, and findings of a fictional product, `acme-gateway`, with fictional advisory and internal IDs, one of them without any signal.

## Usage

Rank one document; the format is detected:

```sh
maat rank --input inputs/trivy.json
```

Combine several documents, in any formats: findings of the same vulnerability and component are merged.

```sh
maat rank --input inputs/trivy.json --input inputs/grype.json --input inputs/osv-scanner.json --input inputs/findings.json
```

The priorities depend on the feed snapshot used: run `maat snapshot show` to see which one.

## Tests

`tests/examples/` runs `maat rank` on these files offline, against feed samples trimmed to their CVEs. When the examples change, update the tests in the same commit.
