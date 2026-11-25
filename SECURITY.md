# Security policy

## Supported versions

Security fixes go into the latest release only. Before 1.0, a fix ships as a patch release of the latest `0.N.x` series: upgrade to it rather than waiting for a backport to an older series.

## Reporting a vulnerability

Do not report a vulnerability in a public issue, pull request or discussion. Report it privately through [GitHub private vulnerability reporting](https://github.com/samy-difallah/maat-vuln/security/advisories/new).

Include what helps reproduce and assess it:

- the version (`maat -V`) and the Python version;
- the command or library call, and the input that triggers the problem;
- the impact you see (what an attacker could read, write or run).

## What happens next

- **Acknowledgement**: within a week.
- **Assessment**: the report is confirmed or declined in the advisory thread, where its details are discussed.
- **Fix**: a confirmed vulnerability is fixed in a patch release and disclosed in a GitHub security advisory once the release is out, crediting the reporter unless they prefer otherwise.

## Scope

The scope is the `maat-vuln` package (library, CLI and input adapters) and this repository's workflows.

Out of scope:

- errors in the data of the feeds Maat reads (CISA KEV, FIRST EPSS, CIRCL Vulnerability-Lookup): report them to their publishers;
- a priority you disagree with: verdicts follow the documented default policy, so open an issue to discuss it.
