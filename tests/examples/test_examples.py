"""End-to-end runs of ``maat rank`` on the documented examples, offline.

Known gaps are strict ``xfail`` tests asserting the expected behavior: a fix
makes them pass, which fails the run until the marker is removed.
"""

import json
from pathlib import Path

import pytest

from maat_vuln import load_findings
from maat_vuln.adapters import load_adapters
from maat_vuln.cli import app
from maat_vuln.models import Flag, Report

EXAMPLES = Path(__file__).parents[2] / "docs" / "examples" / "inputs"

FORMATS = {
    "findings.json": "maat",
    "grype.json": "grype",
    "grype-cyclonedx.json": "cyclonedx",
    "osv-scanner.json": "osv-scanner",
    "trivy.json": "trivy",
    "trivy-cyclonedx.json": "cyclonedx",
}
SCANNERS = ["trivy.json", "grype.json", "osv-scanner.json"]

LOG4SHELL = "CVE-2021-44228"
LOG4SHELL_GHSA = "GHSA-JFH8-C2JP-5V3Q"
RAPID_RESET = "CVE-2023-44487"


def gap(reason):
    """Mark a test asserting the expected behavior of a known gap."""
    return pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason)


def rank(runner, *filenames):
    """Rank example files with the CLI and parse the JSON report."""
    args = ["rank", "--format", "json"]
    for filename in filenames:
        args += ["--input", str(EXAMPLES / filename)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return Report.model_validate_json(result.stdout)


def priorities(report, id_):
    """Priorities of the decisions about one vulnerability ID."""
    return [d.priority for d in report.decisions if d.finding_key.id == id_]


def test_every_example_is_covered():
    """Every JSON example has an expected format below."""
    assert sorted(path.name for path in EXAMPLES.glob("*.json")) == sorted(
        FORMATS
    )


@pytest.mark.parametrize(("filename", "adapter"), FORMATS.items())
def test_example_format(filename, adapter):
    """Each example is detected as its format only and yields findings."""
    document = json.loads((EXAMPLES / filename).read_text(encoding="utf-8"))
    detected = [a.name for a in load_adapters() if a.detect(document)]
    assert detected == [adapter]
    assert load_findings(document)


@pytest.mark.parametrize("filename", SCANNERS)
def test_scanner_finds_log4shell_critical(runner, filename):
    """Every scanner's JSON report ranks Log4Shell CRITICAL, from KEV."""
    report = rank(runner, filename)
    decision = next(
        d for d in report.decisions if d.finding_key.id == LOG4SHELL
    )
    assert decision.priority == "CRITICAL"
    assert decision.rule_id == "p1.kev"


def test_all_examples_together(runner):
    """All examples rank together; each decision is counted once."""
    report = rank(runner, *FORMATS)
    summary = report.summary.model_dump(by_alias=True)
    assert sum(summary.values()) == len(report.decisions)
    assert summary["CRITICAL"] > 0
    assert summary["unscored"] > 0


def test_table(runner):
    """The default table output works on a real scanner report."""
    result = runner.invoke(
        app, ["rank", "--input", str(EXAMPLES / "trivy.json")]
    )
    assert result.exit_code == 0, result.output
    assert LOG4SHELL in result.stdout


def test_go_findings_merge_across_scanners(runner):
    """A Go vulnerability found by several scanners is one decision."""
    report = rank(runner, *SCANNERS)
    assert priorities(report, RAPID_RESET) == ["CRITICAL"]


def test_advisory_with_several_cves(runner):
    """Each CVE of an advisory gets its own signals: one is in KEV."""
    report = rank(runner, "findings.json")
    assert priorities(report, "CVE-2021-45046") == ["CRITICAL"]
    assert priorities(report, "CVE-2021-44832") == ["HIGH"]


def test_osv_related_cves(runner):
    """PYSEC-2023-175 is read through its related CVEs, one in KEV."""
    report = rank(runner, "osv-scanner.json")
    assert "PYSEC-2023-175" not in {d.finding_key.id for d in report.decisions}
    assert priorities(report, "CVE-2023-4863") == ["CRITICAL"]


def test_grype_cyclonedx_has_no_cve(runner):
    """Grype's CycloneDX output gives no CVE: a documented limitation."""
    report = rank(runner, "grype-cyclonedx.json")
    assert all(Flag.UNRESOLVED_ID in d.flags for d in report.decisions)
    assert report.summary.CRITICAL == 0
    assert priorities(report, LOG4SHELL_GHSA) == ["MEDIUM"]


def test_merged_sources_reach_the_report(runner):
    """A decision lists the tools that reported its finding."""
    report = rank(runner, *SCANNERS)
    decision = next(
        d for d in report.decisions if d.finding_key.id == LOG4SHELL
    )
    tools = {source.tool for source in decision.sources}
    assert tools == {"trivy", "grype", "osv-scanner"}
