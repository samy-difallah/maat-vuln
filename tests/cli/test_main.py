"""Tests for the ``maat`` commands."""

import io
import json
import re
from pathlib import Path

import pytest

from maat_vuln.cli import app
from maat_vuln.feeds import CVSS_LOOKUP_URL, EPSS_URL, KEV_URL
from maat_vuln.models import Decision, Report
from maat_vuln.snapshot import Manifest, latest_snapshot

CVSS_ANSWER = json.loads(
    (Path(__file__).parent.parent / "feeds" / "cvss_bulk.json").read_text()
)

IN_KEV = "CVE-2026-106931"
XZ = "CVE-2024-3094"
GHSA = "GHSA-JFH8-C2JP-5V3Q"
PURL = "pkg:deb/debian/xz-utils@5.6.0"
UNKNOWN_SNAPSHOT = "0" * 64
# Click exits with 2 on usage errors.
EXIT_USAGE = 2

IN_KEV_DOCUMENT = json.dumps(
    {
        "schema_version": "0.1.0",
        "findings": [
            {"id": IN_KEV, "cvss": [{"version": "3.1", "base_score": 9.8}]}
        ],
    }
)


class TtyStdin(io.BytesIO):
    """Empty stdin that claims to be a terminal."""

    def isatty(self):
        """Pretend to be interactive."""
        return True


def ranked(result):
    """Parse a JSON report and list its (ID, priority) pairs."""
    assert result.exit_code == 0, result.output
    report = Report.model_validate_json(result.stdout)
    return [(d.finding_key.id, d.priority) for d in report.decisions]


def test_table(runner, snapshot, respx_mock):
    """IDs as arguments give a table, a summary and the snapshot ID."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
    result = runner.invoke(app, ["rank", GHSA, XZ])
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    xz_row = next(line for line in lines if XZ in line)
    assert "P2" in xz_row
    assert "p2.epss_likely" in xz_row
    assert "0.90900" in xz_row
    ghsa_row = next(line for line in lines if GHSA in line)
    assert "none.unscored" in ghsa_row
    assert "unresolved_id" in ghsa_row
    assert lines.index(xz_row) < lines.index(ghsa_row)
    summary = lines.index("P1 0 · P2 1 · P3 0 · P4 0 · unscored 1")
    assert lines[summary + 2] == f"snapshot {snapshot.manifest.snapshot_id}"
    # Blank lines frame the output and set the summary apart.
    assert lines[0] == lines[summary - 1] == lines[summary + 1] == ""
    assert lines[-1] == ""


def test_table_colours(runner, snapshot, monkeypatch):
    """A terminal shows P1 in bold red, in the row and the summary."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = runner.invoke(
        app, ["rank", "--input", "-"], input=IN_KEV_DOCUMENT
    )
    assert result.exit_code == 0, result.output
    assert f"\x1b[1;31m{IN_KEV}" in result.stdout
    assert "\x1b[1;31mP1 1\x1b[0m" in result.stdout


def test_json(runner, snapshot, respx_mock):
    """--format json prints the report alone on stdout."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
    result = runner.invoke(app, ["rank", "--format", "json", GHSA, XZ])
    assert ranked(result) == [(XZ, "P2"), (GHSA, None)]
    report = Report.model_validate_json(result.stdout)
    assert report.snapshot_id == snapshot.manifest.snapshot_id


def test_input_file_with_arguments(runner, snapshot, tmp_path):
    """A JSON input file and ID arguments are ranked together."""
    path = tmp_path / "findings.json"
    path.write_text(IN_KEV_DOCUMENT)
    result = runner.invoke(
        app, ["rank", "--format", "json", "--input", str(path), GHSA]
    )
    assert ranked(result) == [(IN_KEV, "P1"), (GHSA, None)]


def test_input_stdin(runner, snapshot):
    """--input - reads the JSON document from stdin."""
    result = runner.invoke(
        app,
        ["rank", "--format", "json", "--input", "-"],
        input=IN_KEV_DOCUMENT,
    )
    assert ranked(result) == [(IN_KEV, "P1")]


def test_stdin_lines(runner, snapshot, respx_mock):
    """Without IDs or --input, stdin holds one ID per line."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
    result = runner.invoke(
        app,
        ["rank", "--format", "json"],
        input=f"\n{XZ}\n  \n{GHSA.lower()}\n",
    )
    assert ranked(result) == [(XZ, "P2"), (GHSA, None)]


def test_nothing_to_rank(runner, snapshot, monkeypatch):
    """No IDs, no --input and a terminal stdin is a usage error."""
    monkeypatch.setattr(
        "typer.testing.make_input_stream", lambda *_: TtyStdin()
    )
    result = runner.invoke(app, ["rank"])
    assert result.exit_code == EXIT_USAGE
    assert "give IDs" in result.stderr


def test_given_snapshot(runner, snapshot):
    """--snapshot ranks against that snapshot."""
    snapshot_id = snapshot.manifest.snapshot_id
    result = runner.invoke(
        app, ["rank", "--format", "json", "--snapshot", snapshot_id, GHSA]
    )
    assert ranked(result) == [(GHSA, None)]
    assert Report.model_validate_json(result.stdout).snapshot_id == (
        snapshot_id
    )


def test_unknown_snapshot(runner, snapshot):
    """An unknown snapshot ID fails with a message, not a traceback."""
    result = runner.invoke(app, ["rank", "--snapshot", UNKNOWN_SNAPSHOT, GHSA])
    assert result.exit_code == 1
    assert f"unknown snapshot {UNKNOWN_SNAPSHOT}" in result.stderr


def mock_feeds(respx_mock, kev, epss):
    """Serve the KEV and EPSS samples, returning both routes."""
    return (
        respx_mock.get(KEV_URL).respond(200, content=kev),
        respx_mock.get(EPSS_URL).respond(200, content=epss),
    )


def test_refresh(runner, snapshot, respx_mock, kev, epss):
    """--refresh fetches a new snapshot even when one is cached."""
    routes = mock_feeds(respx_mock, kev, epss)
    result = runner.invoke(
        app, ["rank", "--format", "json", "--refresh", GHSA]
    )
    assert ranked(result) == [(GHSA, None)]
    assert all(route.called for route in routes)
    new_id = Report.model_validate_json(result.stdout).snapshot_id
    assert new_id != snapshot.manifest.snapshot_id
    assert latest_snapshot().manifest.snapshot_id == new_id


def test_empty_cache_fetches(runner, respx_mock, kev, epss):
    """With no cached snapshot, one is fetched."""
    mock_feeds(respx_mock, kev, epss)
    result = runner.invoke(app, ["rank", "--format", "json", GHSA])
    assert ranked(result) == [(GHSA, None)]
    assert latest_snapshot() is not None


def test_fetch_failure(runner, respx_mock, epss):
    """A feed that cannot be fetched fails with a message."""
    respx_mock.get(KEV_URL).respond(404)
    respx_mock.get(EPSS_URL).respond(200, content=epss)
    result = runner.invoke(app, ["rank", GHSA])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")


@pytest.mark.parametrize(
    "args",
    [
        ["--snapshot", UNKNOWN_SNAPSHOT, "--refresh"],
        ["--concurrency", "0"],
        ["--format", "xml"],
    ],
)
def test_usage_errors(runner, args):
    """Contradictory or out-of-range options are usage errors."""
    result = runner.invoke(app, ["rank", *args, GHSA])
    assert result.exit_code == EXIT_USAGE


def test_unsupported_schema_version(runner, snapshot):
    """An input document of another major version is refused."""
    result = runner.invoke(
        app,
        ["rank", "--input", "-"],
        input=json.dumps({"schema_version": "1.0.0", "findings": []}),
    )
    assert result.exit_code == 1
    assert "unsupported schema_version 1.0.0" in result.stderr


def test_snapshot_fetch(runner, respx_mock, kev, epss):
    """Fetching prints the ID of the new, now latest, snapshot."""
    mock_feeds(respx_mock, kev, epss)
    result = runner.invoke(app, ["snapshot", "fetch"])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == latest_snapshot().manifest.snapshot_id


def test_snapshot_fetch_failure(runner, respx_mock, epss):
    """A feed that cannot be fetched fails with a message."""
    respx_mock.get(KEV_URL).respond(404)
    respx_mock.get(EPSS_URL).respond(200, content=epss)
    result = runner.invoke(app, ["snapshot", "fetch"])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")


@pytest.mark.parametrize("given", [False, True])
def test_snapshot_show(runner, snapshot, given):
    """Show prints the latest or given snapshot and its feeds."""
    snapshot_id = snapshot.manifest.snapshot_id
    args = [snapshot_id] if given else []
    result = runner.invoke(app, ["snapshot", "show", *args])
    assert result.exit_code == 0, result.output
    assert f"snapshot {snapshot_id}" in result.stdout
    assert "cached CVSS lookups 0" in result.stdout
    for feed in snapshot.manifest.feeds:
        row = next(
            line for line in result.stdout.splitlines() if feed.url in line
        )
        assert feed.name in row
        assert feed.sha256 in row


def test_snapshot_show_json(runner, snapshot):
    """--format json prints the manifest."""
    result = runner.invoke(app, ["snapshot", "show", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert Manifest.model_validate_json(result.stdout) == snapshot.manifest


def test_snapshot_show_empty_cache(runner):
    """With no snapshot cached, show points to snapshot fetch."""
    result = runner.invoke(app, ["snapshot", "show"])
    assert result.exit_code == 1
    assert "run maat snapshot fetch" in result.stderr


def test_snapshot_show_unknown(runner, snapshot):
    """An unknown snapshot ID fails with a message."""
    result = runner.invoke(app, ["snapshot", "show", UNKNOWN_SNAPSHOT])
    assert result.exit_code == 1
    assert f"unknown snapshot {UNKNOWN_SNAPSHOT}" in result.stderr


def explained(result):
    """Map each label of an explanation to its first value line."""
    assert result.exit_code == 0, result.output
    pairs = (
        re.split(r"\s{2,}", line.strip(), maxsplit=1)
        for line in result.stdout.splitlines()
        if line and not line[0].isspace()
    )
    return {label: value for label, value in pairs}


def test_explain_kev(runner, snapshot):
    """A CVE in KEV is P1, with its KEV dates and the KEV feed source."""
    fields = explained(runner.invoke(app, ["explain", IN_KEV.lower()]))
    assert fields["ID"] == IN_KEV
    assert fields["Priority"] == "P1"
    assert fields["Rule"] == "p1.kev"
    assert fields["KEV"].startswith("in KEV, added 2026-10-20, due 2026-10")
    assert fields["KEV source"].startswith("https://example.org/kev.json")
    assert fields["Snapshot"] == snapshot.manifest.snapshot_id


def test_explain_signals(runner, snapshot, respx_mock):
    """Thresholds, EPSS and looked-up CVSS values are all shown."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
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
    assert fields["KEV"] == "not computed"
    assert "unresolved_id" in fields["Flags"]
    assert "KEV source" not in fields


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
