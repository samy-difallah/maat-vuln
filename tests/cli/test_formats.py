"""Tests for ``maat formats``."""

from maat_vuln.cli import app


def test_formats(runner):
    """Every built-in format is listed, one name per line, sorted."""
    result = runner.invoke(app, ["formats"])
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [
        "cyclonedx",
        "grype",
        "maat",
        "osv-scanner",
        "trivy",
    ]
