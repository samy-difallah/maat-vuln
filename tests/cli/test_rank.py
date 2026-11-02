"""Tests for ``maat rank``."""

import io
import json

import pytest

from maat_vuln.cli import app
from maat_vuln.feeds import CVSS_LOOKUP_URL, EPSS_URL, KEV_URL
from maat_vuln.models import Report
from maat_vuln.snapshot import latest_snapshot

IN_KEV = "CVE-2026-106931"
XZ = "CVE-2024-3094"
GHSA = "GHSA-JFH8-C2JP-5V3Q"
PURL = "pkg:deb/debian/xz-utils@5.6.0"
UNKNOWN_SNAPSHOT = "0" * 64
# Click exits with 2 on usage errors.
EXIT_USAGE = 2
NARROW = 80

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


def test_table(runner, snapshot, respx_mock, cvss_answer):
    """IDs as arguments give a table, a summary and the snapshot ID."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(app, ["rank", GHSA, XZ])
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    xz_row = next(line for line in lines if XZ in line)
    assert "P2" in xz_row
    assert "p2.epss_likely" in xz_row
    assert "0.90900" in xz_row
    ghsa_row = next(line for line in lines if GHSA in line)
    assert "none.unscored" in ghsa_row
    # One flag per line, under the first.
    ghsa = lines.index(ghsa_row)
    flags = [line.split()[-1] for line in lines[ghsa : ghsa + 4]]
    assert flags == [
        "cvss_missing",
        "epss_missing",
        "unresolved_id",
        "unscored",
    ]
    assert lines.index(xz_row) < ghsa
    # No finding has a component: the column is left out.
    assert "Component" not in result.stdout
    summary = lines.index("P1 0 · P2 1 · P3 0 · P4 0 · unscored 1")
    assert lines[summary + 2] == f"snapshot {snapshot.manifest.snapshot_id}"
    # Blank lines frame the output and set the summary apart.
    assert lines[0] == lines[summary - 1] == lines[summary + 1] == ""
    assert lines[-1] == ""


def test_table_narrow(runner, snapshot, respx_mock, cvss_answer, monkeypatch):
    """On a narrow terminal, IDs and scores stay whole; the component folds."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    monkeypatch.setenv("COLUMNS", str(NARROW))
    document = json.dumps(
        {"findings": [{"id": XZ, "component": {"purl": PURL}}, {"id": GHSA}]}
    )
    result = runner.invoke(app, ["rank", "--input", "-"], input=document)
    assert result.exit_code == 0, result.output
    assert max(len(line) for line in result.stdout.splitlines()) <= NARROW
    for whole in (XZ, GHSA, "0.90900", "0.998", "10.0"):
        assert whole in result.stdout
    assert "…" not in result.stdout
    assert "pkg:" in result.stdout


def test_table_colours(runner, snapshot, monkeypatch):
    """A terminal shows P1 in bold red, in the row and the summary."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = runner.invoke(
        app, ["rank", "--input", "-"], input=IN_KEV_DOCUMENT
    )
    assert result.exit_code == 0, result.output
    assert f"\x1b[1;31m{IN_KEV}" in result.stdout
    assert "\x1b[1;31mP1 1\x1b[0m" in result.stdout


def test_json(runner, snapshot, respx_mock, cvss_answer):
    """--format json prints the report alone on stdout."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
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


def test_stdin_lines(runner, snapshot, respx_mock, cvss_answer):
    """Without IDs or --input, stdin holds one ID per line."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
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


def test_refresh(runner, snapshot, feeds):
    """--refresh fetches a new snapshot even when one is cached."""
    result = runner.invoke(
        app, ["rank", "--format", "json", "--refresh", GHSA]
    )
    assert ranked(result) == [(GHSA, None)]
    assert all(route.called for route in feeds)
    new_id = Report.model_validate_json(result.stdout).snapshot_id
    assert new_id != snapshot.manifest.snapshot_id
    assert latest_snapshot().manifest.snapshot_id == new_id


def test_empty_cache_fetches(runner, feeds):
    """With no cached snapshot, one is fetched."""
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


@pytest.mark.parametrize(
    ("args", "stdin", "message"),
    [
        (
            ["cve-list.txt"],
            None,
            "Error: id: malformed CVE ID CVE-LIST.TXT, expected CVE-YYYY-NNNN",
        ),
        (
            ["--input", "-"],
            json.dumps({"findings": [{"id": GHSA, "aliases": ["CVE-1"]}]}),
            "Error: findings.0.aliases.0: malformed CVE ID CVE-1,"
            " expected CVE-YYYY-NNNN",
        ),
    ],
)
def test_invalid_input(runner, snapshot, args, stdin, message):
    """Invalid input fails with one line naming the field and reason."""
    result = runner.invoke(app, ["rank", *args], input=stdin)
    assert result.exit_code == 1
    assert result.stderr == message + "\n"
