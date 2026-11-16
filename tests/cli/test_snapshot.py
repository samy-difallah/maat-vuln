"""Tests for ``maat snapshot fetch``, ``list`` and ``show``."""

import re
from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter

from maat_vuln.cli import app
from maat_vuln.feeds import EPSS_URL, KEV_URL
from maat_vuln.snapshot import (
    Manifest,
    RawFeed,
    create_snapshot,
    default_root,
    latest_snapshot,
)

UNKNOWN_SNAPSHOT = "0" * 64


def is_id(word):
    """Tell whether a word is a snapshot ID."""
    return re.fullmatch(r"[0-9a-f]{64}", word) is not None


def test_snapshot_fetch(runner, feeds):
    """Fetching prints the ID of the new, now latest, snapshot.

    Each feed's version goes to stderr, keeping stdout to the ID alone.
    """
    result = runner.invoke(app, ["snapshot", "fetch"])
    assert result.exit_code == 0, result.output
    manifest = latest_snapshot().manifest
    assert result.stdout == f"{manifest.snapshot_id}\n"
    lines = result.stderr.splitlines()
    assert len(lines) == len(manifest.feeds)
    for line, feed in zip(lines, manifest.feeds, strict=True):
        assert line.split()[0] == feed.name
        for key, value in feed.version.items():
            assert f"{key} {value}" in line


def test_snapshot_fetch_failure(runner, respx_mock, epss):
    """A feed that cannot be fetched fails with a message."""
    respx_mock.get(KEV_URL).respond(404)
    respx_mock.get(EPSS_URL).respond(200, content=epss)
    result = runner.invoke(app, ["snapshot", "fetch"])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")


@pytest.mark.parametrize("given", [False, True])
def test_snapshot_show(runner, snapshot, given, monkeypatch):
    """Show prints the latest or given snapshot, then a block per feed.

    Long values stay on one line even in a narrow terminal, so they
    copy in one piece.
    """
    monkeypatch.setenv("COLUMNS", "40")
    snapshot_id = snapshot.manifest.snapshot_id
    args = [snapshot_id] if given else []
    result = runner.invoke(app, ["snapshot", "show", *args])
    assert result.exit_code == 0, result.output
    lines = [line.split() for line in result.stdout.splitlines()]
    assert ["Snapshot", snapshot_id] in lines
    created = next(line[1] for line in lines if line[:1] == ["Created"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created)
    assert ["CVSS", "lookups", "0"] in lines
    for feed in snapshot.manifest.feeds:
        block = lines[lines.index([feed.name]) :][:4]
        assert block[1:] == [
            ["retrieved", "2026-10-22T12:00:00Z"],
            ["url", feed.url],
            ["sha256", feed.sha256],
        ]


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


@pytest.fixture
def newer(snapshot):
    """Second snapshot, created after the ``snapshot`` fixture."""
    return create_snapshot(
        [
            RawFeed(
                name="kev",
                url="https://example.org/kev.json",
                filename="kev.json",
                retrieved_at=datetime(2026, 10, 23, 12, tzinfo=UTC),
                version={"catalogVersion": "2026.10.23"},
                content=b"{}",
            )
        ],
        root=default_root(),
    )


def test_snapshot_list(runner, snapshot, newer):
    """List prints one block per snapshot, newest first."""
    result = runner.invoke(app, ["snapshot", "list"])
    assert result.exit_code == 0, result.output
    lines = [line.split() for line in result.stdout.splitlines()]
    ids = [line[0] for line in lines if line[:1] and is_id(line[0])]
    assert ids == [newer.manifest.snapshot_id, snapshot.manifest.snapshot_id]
    assert ["kev", "catalogVersion", "2026.10.23"] in lines
    assert lines.count(["CVSS", "lookups", "0"]) == len(ids)


def test_snapshot_list_json(runner, snapshot, newer):
    """--format json prints the manifests, newest first."""
    result = runner.invoke(app, ["snapshot", "list", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert TypeAdapter(list[Manifest]).validate_json(result.stdout) == [
        newer.manifest,
        snapshot.manifest,
    ]


@pytest.mark.parametrize("output", ["table", "json"])
def test_snapshot_list_empty_cache(runner, output):
    """An empty cache is no error: JSON gets ``[]``, the table a note."""
    result = runner.invoke(app, ["snapshot", "list", "--format", output])
    assert result.exit_code == 0, result.output
    if output == "json":
        assert result.stdout == "[]\n"
    else:
        assert result.stdout == ""
        assert "run maat snapshot fetch" in result.stderr
