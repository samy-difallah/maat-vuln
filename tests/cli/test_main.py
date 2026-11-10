"""Tests for the ``maat`` app's global options."""

from importlib.metadata import version

import pytest

from maat_vuln.cli import app


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version(runner, flag):
    """The version option prints the package version, even before a command.

    Being eager, it exits before the command would run.
    """
    expected = f"maat-vuln {version('maat-vuln')}\n"
    for args in ([flag], [flag, "rank", "CVE-2021-44228"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert result.stdout == expected
