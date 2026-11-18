"""Tests for the ``maat.toml`` config file."""

import json

import pytest
from rich.text import Text

from maat_vuln.cli import app
from maat_vuln.engine import prioritize
from maat_vuln.models import Report
from maat_vuln.snapshot import SNAPSHOTS_DIR

GHSA = "GHSA-JFH8-C2JP-5V3Q"
IN_KEV = "CVE-2026-106931"
# Click exits with 2 on usage errors.
EXIT_USAGE = 2
EXIT_ERROR = 1
STALE_WARNING = "Warning: the latest snapshot is 30 hours old"


@pytest.fixture
def config(tmp_path, monkeypatch):
    """Work in a temporary directory; return a writer of its maat.toml."""
    monkeypatch.chdir(tmp_path)

    def write(text, name="maat.toml"):
        """Write a config file, ``./maat.toml`` by default."""
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    return write


def is_json(result):
    """Tell whether a successful command printed JSON."""
    assert result.exit_code == 0, result.output
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return True


@pytest.mark.parametrize(
    "command",
    [
        ["rank", GHSA],
        ["explain", GHSA],
        ["snapshot", "show"],
        ["snapshot", "list"],
    ],
)
def test_format(runner, snapshot, config, command):
    """``format`` sets every command's --format."""
    config('format = "json"\n')
    assert is_json(runner.invoke(app, command))


@pytest.mark.parametrize(
    ("args", "env", "expected"),
    [
        ([], {}, True),
        ([], {"MAAT_FORMAT": "table"}, False),
        (["--format", "table"], {}, False),
        (["--format", "json"], {"MAAT_FORMAT": "table"}, True),
    ],
)
def test_precedence(runner, snapshot, config, args, env, expected):
    """A flag beats its variable, which beats the config file."""
    config('format = "json"\n')
    result = runner.invoke(app, ["rank", *args, GHSA], env=env)
    assert is_json(result) is expected


def test_rank_keys(runner, snapshot, config, monkeypatch):
    """``concurrency`` and ``min_priority`` set those options of rank."""
    seen = []

    def spy(findings, snapshot, concurrency):
        """Record the concurrency the CLI passes."""
        seen.append(concurrency)
        return prioritize(findings, snapshot, concurrency)

    monkeypatch.setattr("maat_vuln.cli.rank.prioritize", spy)
    config('format = "json"\nconcurrency = 3\nmin_priority = "CRITICAL"\n')
    result = runner.invoke(app, ["rank", IN_KEV, GHSA])
    assert result.exit_code == 0, result.output
    report = Report.model_validate_json(result.stdout)
    assert [d.finding_key.id for d in report.decisions] == [IN_KEV]
    assert seen == [3]


def test_max_age(runner, snapshot, config, aged, feeds):
    """``max_age`` replaces an old snapshot, and gives way to --snapshot."""
    aged(30)
    config('format = "json"\nmax_age = 12\n')
    snapshot_id = snapshot.manifest.snapshot_id
    for args, fetched in (([], True), (["--snapshot", snapshot_id], False)):
        result = runner.invoke(app, ["rank", *args, GHSA])
        assert result.exit_code == 0, result.output
        report = Report.model_validate_json(result.stdout)
        assert (report.snapshot_id != snapshot_id) is fetched


@pytest.mark.parametrize(
    ("stale_after", "warned"), [(None, True), (48, False)]
)
def test_stale_after(runner, config, aged, stale_after, warned):
    """``stale_after`` sets the age of the stale snapshot warning."""
    aged(30)
    if stale_after is not None:
        config(f"stale_after = {stale_after}\n")
    result = runner.invoke(app, ["rank", GHSA])
    assert result.exit_code == 0, result.output
    assert (STALE_WARNING in result.stderr) is warned


def test_cache_dir(runner, feeds, config, tmp_path):
    """``cache_dir`` is relative to the config file's directory."""
    path = config('cache_dir = "cache"\n', name="conf/maat.toml")
    result = runner.invoke(app, ["--config", str(path), "snapshot", "fetch"])
    assert result.exit_code == 0, result.output
    snapshot_id = result.stdout.strip()
    assert (tmp_path / "conf" / "cache" / SNAPSHOTS_DIR / snapshot_id).is_dir()


def test_config_option_replaces_local_file(runner, snapshot, config):
    """``--config`` is the only file read, ``./maat.toml`` is ignored."""
    config('format = "json"\n')
    path = config("", name="other.toml")
    result = runner.invoke(app, ["--config", str(path), "rank", GHSA])
    assert not is_json(result)


def test_missing_config_option_file(runner, config):
    """A missing ``--config`` file is a usage error."""
    result = runner.invoke(app, ["--config", "missing.toml", "formats"])
    assert result.exit_code == EXIT_USAGE
    assert "does not exist" in Text.from_ansi(result.stderr).plain


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("colour = true\n", "colour: Extra inputs are not permitted"),
        (
            'concurrency = "8"\n',
            "concurrency: Input should be a valid integer",
        ),
        ("max_age = 0\n", "max_age: Input should be greater than 0"),
        ('format = "xml"\n', "format: Input should be 'table' or 'json'"),
        ("format =\n", "Invalid value (at line 1, column 9)"),
    ],
)
def test_invalid(runner, config, text, error):
    """A wrong key, type or syntax is an error, even under -q."""
    config(text)
    result = runner.invoke(app, ["rank", "-q", GHSA])
    assert result.exit_code == EXIT_ERROR
    assert result.stderr == f"Error: maat.toml: {error}\n"
