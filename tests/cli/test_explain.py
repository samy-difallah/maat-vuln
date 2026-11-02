"""Tests for ``maat explain``."""

import re

import pytest

from maat_vuln.cli import app
from maat_vuln.feeds import CVSS_LOOKUP_URL
from maat_vuln.models import Decision

IN_KEV = "CVE-2026-106931"
XZ = "CVE-2024-3094"
GHSA = "GHSA-JFH8-C2JP-5V3Q"
PURL = "pkg:deb/debian/xz-utils@5.6.0"
UNKNOWN_SNAPSHOT = "0" * 64
# Click exits with 2 on usage errors.
EXIT_USAGE = 2


def explained(result):
    """Map each label of an explanation to its first value line."""
    assert result.exit_code == 0, result.output
    pairs = (
        re.split(r"\s{2,}", line.strip(), maxsplit=1)
        for line in result.stdout.splitlines()
        if line and not line[0].isspace()
    )
    return {label: value for label, value in pairs}


def test_explain_kev(runner, snapshot, monkeypatch):
    """A CVE in KEV is P1, with its KEV dates and the KEV feed source.

    Fields the decision leaves empty are left out, and long values stay
    on one line even in a narrow terminal, so they copy in one piece.
    """
    monkeypatch.setenv("COLUMNS", "40")
    result = runner.invoke(app, ["explain", IN_KEV.lower()])
    fields = explained(result)
    assert fields["ID"] == IN_KEV
    assert fields["Priority"] == "P1"
    assert fields["Rule"] == "p1.kev"
    assert fields["KEV"] == (
        "in KEV, added 2026-10-20, due 2026-10-23, ransomware use unknown"
    )
    assert fields["KEV source"] == (
        "https://example.org/kev.json, retrieved 2026-10-22T12:00:00Z"
    )
    assert fields["Snapshot"] == snapshot.manifest.snapshot_id
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", fields["Created"])
    for empty in ("Component", "Thresholds"):
        assert empty not in fields
    # A blank line opens each block: verdict, rule, signals, provenance.
    lines = result.stdout.splitlines()
    assert [
        lines[i + 1].split()[0]
        for i, line in enumerate(lines[:-1])
        if not line
    ] == ["ID", "Rule", "KEV", "Snapshot"]
    assert lines[-1] == ""


def test_explain_signals(runner, snapshot, respx_mock, cvss_answer):
    """Thresholds, EPSS and looked-up CVSS values are all shown."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(app, ["explain", XZ, "--component", PURL])
    fields = explained(result)
    assert fields["Component"] == PURL
    assert fields["Rule"] == "p2.epss_likely"
    assert fields["Thresholds"] == "EPSS_LIKELY 0.1, CVSS_LOW_CAP 4.0"
    assert fields["EPSS"].startswith("probability 0.90900, percentile")
    assert fields["EPSS source"].startswith("https://example.org/epss")
    assert "(vulnerability-lookup) selected" in result.stdout


def test_explain_unresolved(runner, snapshot):
    """A non-CVE ID is unscored: its feed signals were never computed."""
    fields = explained(runner.invoke(app, ["explain", GHSA]))
    assert fields["Priority"] == "unscored"
    assert fields["KEV"] == "not computed, no CVE ID"
    assert "unresolved_id" in fields["Flags"]
    assert "KEV source" not in fields


def test_explain_lookup_failed(runner, snapshot, respx_mock):
    """A failed CVSS lookup is told apart from a CVSS never computed."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(400)
    fields = explained(runner.invoke(app, ["explain", XZ]))
    assert fields["CVSS"] == "lookup failed, retried on the next run"
    assert "cvss_lookup_failed" in fields["Flags"]


def test_explain_json(runner, snapshot):
    """--format json prints the decision, component included."""
    snapshot_id = snapshot.manifest.snapshot_id
    result = runner.invoke(
        app,
        [
            "explain",
            IN_KEV,
            "--component",
            PURL,
            "--format",
            "json",
            "--snapshot",
            snapshot_id,
        ],
    )
    assert result.exit_code == 0, result.output
    decision = Decision.model_validate_json(result.stdout)
    assert decision.finding_key.component == PURL
    assert decision.priority == "P1"
    assert decision.snapshot_id == snapshot_id


@pytest.mark.parametrize(
    ("args", "exit_code", "message"),
    [
        (["--snapshot", UNKNOWN_SNAPSHOT], 1, "unknown snapshot"),
        (["--snapshot", UNKNOWN_SNAPSHOT, "--refresh"], EXIT_USAGE, ""),
    ],
)
def test_explain_snapshot_errors(runner, args, exit_code, message):
    """Unknown or contradictory snapshot options fail."""
    result = runner.invoke(app, ["explain", IN_KEV, *args])
    assert result.exit_code == exit_code
    assert message in result.stderr


def test_explain_invalid_id(runner, snapshot):
    """A blank ID fails with a message, not a traceback."""
    result = runner.invoke(app, ["explain", " "])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")
