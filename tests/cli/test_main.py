"""Tests for the ``maat`` app's global options."""

import json
from importlib.metadata import version

import pytest
from rich.text import Text

from maat_vuln.cli import app
from maat_vuln.snapshot import SNAPSHOTS_DIR, latest_snapshot

GHSA = "GHSA-JFH8-C2JP-5V3Q"
# Click exits with 2 on usage errors.
EXIT_USAGE = 2


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


@pytest.mark.parametrize("by_env", [False, True])
def test_cache_dir(runner, feeds, tmp_path, monkeypatch, by_env):
    """Every command keeps its snapshots in the given cache directory.

    The flag and its environment variable work alike; the user cache
    is left untouched.
    """
    cache_dir = tmp_path / "elsewhere"
    if by_env:
        monkeypatch.setenv("MAAT_CACHE_DIR", str(cache_dir))
        option = []
    else:
        option = ["--cache-dir", str(cache_dir)]
    fetched = runner.invoke(app, [*option, "snapshot", "fetch"])
    assert fetched.exit_code == 0, fetched.output
    snapshot_id = fetched.stdout.strip()
    assert (cache_dir / SNAPSHOTS_DIR / snapshot_id).is_dir()
    assert latest_snapshot() is None
    for command in (
        ["snapshot", "show"],
        ["rank", GHSA],
        ["explain", GHSA],
    ):
        result = runner.invoke(app, [*option, *command, "--format", "json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["snapshot_id"] == snapshot_id
    # Reused, never fetched again.
    assert all(route.call_count == 1 for route in feeds)


def test_cache_dir_file(runner, tmp_path):
    """A file given as the cache directory is a usage error."""
    path = tmp_path / "file"
    path.touch()
    result = runner.invoke(app, ["--cache-dir", str(path), "snapshot", "show"])
    assert result.exit_code == EXIT_USAGE
    assert "is a file" in Text.from_ansi(result.stderr).plain
