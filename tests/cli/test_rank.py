"""Tests for ``maat rank``."""

import io
import json
import logging

import pytest

from maat_vuln.cli import app
from maat_vuln.feeds import CVSS_LOOKUP_URL, EPSS_URL, KEV_URL
from maat_vuln.models import Report
from maat_vuln.snapshot import default_root, latest_snapshot

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
    # Processing steps are only shown in verbose mode.
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    xz_row = next(line for line in lines if XZ in line)
    assert "HIGH (P2)" in xz_row
    assert "p2.epss_likely" in xz_row
    assert "0.90900" in xz_row
    ghsa_row = next(line for line in lines if GHSA in line)
    assert ghsa_row.startswith("unscored ")
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
    summary = lines.index(
        "CRITICAL 0 · HIGH 1 · MEDIUM 0 · LOW 0 · unscored 1"
    )
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
    """A terminal shows CRITICAL in bold red, in the row and the summary."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = runner.invoke(
        app, ["rank", "--input", "-"], input=IN_KEV_DOCUMENT
    )
    assert result.exit_code == 0, result.output
    assert f"\x1b[1;31m{IN_KEV}" in result.stdout
    assert "\x1b[1;31mCRITICAL 1\x1b[0m" in result.stdout


def test_json(runner, snapshot, respx_mock, cvss_answer):
    """--format json prints the report alone on stdout."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(app, ["rank", "--format", "json", GHSA, XZ])
    assert ranked(result) == [(XZ, "HIGH"), (GHSA, None)]
    report = Report.model_validate_json(result.stdout)
    assert report.snapshot_id == snapshot.manifest.snapshot_id


def test_input_file_with_arguments(runner, snapshot, tmp_path):
    """A JSON input file and ID arguments are ranked together."""
    path = tmp_path / "findings.json"
    path.write_text(IN_KEV_DOCUMENT)
    result = runner.invoke(
        app, ["rank", "--format", "json", "--input", str(path), GHSA]
    )
    assert ranked(result) == [(IN_KEV, "CRITICAL"), (GHSA, None)]


def test_input_stdin(runner, snapshot):
    """--input - reads the JSON document from stdin."""
    result = runner.invoke(
        app,
        ["rank", "--format", "json", "--input", "-"],
        input=IN_KEV_DOCUMENT,
    )
    assert ranked(result) == [(IN_KEV, "CRITICAL")]


def test_inputs_in_several_formats(runner, snapshot, tmp_path):
    """Repeated --input documents of any format merge with ID arguments."""
    native = {
        "findings": [
            {
                "id": IN_KEV,
                "component": {"purl": PURL},
                "cvss": [{"version": "3.1", "base_score": 9.8}],
            }
        ]
    }
    trivy = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": IN_KEV,
                        "PkgIdentifier": {"PURL": PURL},
                    }
                ]
            }
        ],
    }
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(trivy))
    args = ["--input", str(path), "--input", "-", GHSA]
    result = runner.invoke(
        app, ["rank", "--format", "json", *args], input=json.dumps(native)
    )
    assert ranked(result) == [(IN_KEV, "CRITICAL"), (GHSA, None)]
    report = Report.model_validate_json(result.stdout)
    assert report.decisions[0].finding_key.component == PURL


def test_stdin_input_twice(runner, snapshot):
    """'-' can be given to --input only once."""
    result = runner.invoke(
        app, ["rank", "--input", "-", "--input", "-"], input=IN_KEV_DOCUMENT
    )
    assert result.exit_code == EXIT_USAGE
    assert "'-' (stdin) can be given only once" in result.stderr


def test_stdin_lines(runner, snapshot, respx_mock, cvss_answer):
    """Without IDs or --input, stdin holds one ID per line."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(
        app,
        ["rank", "--format", "json"],
        input=f"\n{XZ}\n  \n{GHSA.lower()}\n",
    )
    assert ranked(result) == [(XZ, "HIGH"), (GHSA, None)]


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


def in_order(lines, prefixes):
    """Tell whether lines start with the prefixes in order, gaps allowed."""
    remaining = iter(lines)
    return all(
        any(line.startswith(prefix) for line in remaining)
        for prefix in prefixes
    )


@pytest.mark.parametrize("output", ["table", "json"])
def test_quiet(runner, snapshot, respx_mock, cvss_answer, output):
    """Quiet ranking prints nothing, in any format."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(app, ["rank", "-q", "--format", output, XZ])
    assert result.exit_code == 0, result.output
    assert result.stdout == result.stderr == ""


def test_quiet_error(runner, snapshot):
    """Quiet ranking silences errors: only the exit code tells."""
    result = runner.invoke(
        app, ["rank", "-q", "--snapshot", UNKNOWN_SNAPSHOT, GHSA]
    )
    assert result.exit_code == 1
    assert result.stdout == result.stderr == ""


def test_quiet_usage_error(runner):
    """Quiet ranking still reports errors in the command line."""
    result = runner.invoke(
        app, ["rank", "-q", "--snapshot", UNKNOWN_SNAPSHOT, "--refresh", GHSA]
    )
    assert result.exit_code == EXIT_USAGE
    assert "cannot be combined with --snapshot" in result.stderr


def test_verbose(runner, feeds, respx_mock, cvss_answer):
    """Verbose ranking prints every step on stderr, the result on stdout."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=cvss_answer)
    result = runner.invoke(
        app, ["rank", "-v", "--input", "-", XZ, GHSA], input=IN_KEV_DOCUMENT
    )
    assert result.exit_code == 0, result.output
    assert IN_KEV in result.stdout
    assert "Decisions:" not in result.stdout
    logs = result.stderr.splitlines()
    # A blank line first, as the report starts with one.
    assert logs[0] == ""
    assert in_order(
        logs,
        [
            "IDs from the command line: 2",
            "Detected the maat format",
            "Findings from <stdin>: 1",
            f"Looking for the latest snapshot in {default_root()}",
            "No snapshot in the cache: fetching a new one",
            "Fetching the KEV and EPSS feeds",
            "Fetched the kev feed: ",
            "Fetched the epss feed: ",
            "Created snapshot ",
            "Findings: read 3, kept 3 ",
            "Vulnerabilities: 3, CVEs 2",
            "Reading the kev feed: ",
            "KEV: listed 1, not listed 1",
            "Reading the epss feed: ",
            "EPSS: scored 1, not scored 1",
            "CVSS: from the input 1, cached in the snapshot 0, to look up 1",
            "Looking up CVSS in Vulnerability-Lookup: CVEs 1, requests 1",
            f"POST {CVSS_LOOKUP_URL}: HTTP 200, ",
            "CVSS lookup: found 1, no CVSS 0, failed 0;",
            "Decisions: 3, CRITICAL 1, HIGH 1, MEDIUM 0, LOW 0, unscored 1",
        ],
    ), logs
    for url in (KEV_URL, EPSS_URL):
        assert any(line.startswith(f"GET {url}: HTTP 200") for line in logs)


def test_verbose_colour(runner, snapshot, monkeypatch):
    """A terminal shows the steps in grey; the handler goes with the run."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = runner.invoke(app, ["rank", "-v", GHSA])
    assert result.exit_code == 0, result.output
    step = next(line for line in result.stderr.splitlines() if line)
    assert step.startswith("\x1b[")
    assert "IDs from the command line: 1" in step
    assert not logging.getLogger("maat_vuln").handlers


def test_quiet_and_verbose(runner):
    """Quiet and verbose modes cannot be combined."""
    result = runner.invoke(app, ["rank", "-q", "-v", GHSA])
    assert result.exit_code == EXIT_USAGE
    assert "cannot be combined with --verbose" in result.stderr


@pytest.mark.parametrize(
    ("args", "step"),
    [
        ([], "Using the latest snapshot {id}, created "),
        (["--snapshot", "{id}"], "Loading snapshot {id}, given by --snapshot"),
        (["--refresh"], "Fetching a new snapshot, as --refresh asks"),
    ],
)
def test_verbose_snapshot_choice(runner, snapshot, request, args, step):
    """Verbose ranking tells which snapshot it uses, and why."""
    if "--refresh" in args:
        request.getfixturevalue("feeds")
    snapshot_id = snapshot.manifest.snapshot_id
    args = [arg.format(id=snapshot_id) for arg in args]
    result = runner.invoke(app, ["rank", "-v", *args, GHSA])
    assert result.exit_code == 0, result.output
    assert in_order(result.stderr.splitlines(), [step.format(id=snapshot_id)])


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
        (
            ["--input", "-"],
            json.dumps({"unknown": []}),
            "Error: unrecognized input format,"
            " supported: cyclonedx, grype, maat, osv-scanner, trivy",
        ),
        (
            ["--input", "-"],
            "CVE-2024-0001",
            "Error: invalid JSON input: Expecting value:"
            " line 1 column 1 (char 0)",
        ),
    ],
)
def test_invalid_input(runner, snapshot, args, stdin, message):
    """Invalid input fails with one line naming the field and reason."""
    result = runner.invoke(app, ["rank", *args], input=stdin)
    assert result.exit_code == 1
    assert result.stderr == message + "\n"
