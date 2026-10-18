# Maât

Exploitation-driven vulnerability prioritization, as a Python library with a thin CLI on top. Maât ranks vulnerabilities with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/), with CVSS as a secondary signal. Every verdict comes from a named rule, is explained, and is tied to a dated, hashed snapshot of the feeds.

## Status

Maât is under development: no version has been released yet.

## Roadmap

- **v0.1** (planned): reproducible core. P1–P4 verdicts from KEV, EPSS and CVSS with an explanation for each, dated and hashed feed snapshots, table and JSON output, CLI and Python library.
- **v0.2** (planned): SCA inputs. CycloneDX (including VDR), Trivy, Grype and OSV-Scanner, with multi-source merge and provenance.
- **v0.3** (planned): outputs and CI. SARIF, Markdown and enriched CycloneDX output, a `--fail-on` threshold and a GitHub Action.
- **Later**: VEX support (v0.4) and policies as code (v0.5).

## Contributing

See [CONTRIBUTING.md](https://github.com/samy-difallah/maat-vuln/blob/main/CONTRIBUTING.md).

## License

[Apache-2.0](https://github.com/samy-difallah/maat-vuln/blob/main/LICENSE).
