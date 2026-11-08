"""Fixtures for the CLI tests: an isolated cache, feed samples, a snapshot."""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from maat_vuln.feeds import EPSS_FILENAME, EPSS_URL, KEV_FILENAME, KEV_URL
from maat_vuln.snapshot import RawFeed, create_snapshot, default_root

# Trimmed real feed samples, shared with the feed client tests.
FEEDS_DIR = Path(__file__).parents[1] / "feeds" / "fixtures"


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    """Point the user cache to a temporary directory, never the real one.

    platformdirs reads XDG_CACHE_HOME on Linux, where CI runs.
    """
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    # Wide enough for Rich never to wrap a table cell.
    monkeypatch.setenv("COLUMNS", "200")
    return tmp_path


@pytest.fixture
def kev():
    """Raw KEV catalog sample."""
    return (FEEDS_DIR / "kev.json").read_bytes()


@pytest.fixture
def epss():
    """Raw EPSS scores sample, gzipped as served."""
    return gzip.compress((FEEDS_DIR / "epss.csv").read_bytes())


@pytest.fixture
def cvss_answer():
    """Vulnerability-Lookup bulk answer sample."""
    return json.loads((FEEDS_DIR / "cvss_bulk.json").read_text())


@pytest.fixture
def feeds(respx_mock, kev, epss):
    """Serve the KEV and EPSS samples, returning both routes."""
    return (
        respx_mock.get(KEV_URL).respond(200, content=kev),
        respx_mock.get(EPSS_URL).respond(200, content=epss),
    )


@pytest.fixture
def snapshot(kev, epss):
    """Snapshot of the KEV and EPSS samples in the user cache."""
    feeds = [("kev", KEV_FILENAME, kev), ("epss", EPSS_FILENAME, epss)]
    return create_snapshot(
        [
            RawFeed(
                name=name,
                url=f"https://example.org/{filename}",
                filename=filename,
                retrieved_at=datetime(2026, 10, 22, 12, tzinfo=UTC),
                version={},
                content=content,
            )
            for name, filename, content in feeds
        ],
        root=default_root(),
    )


@pytest.fixture
def runner():
    """CLI runner keeping stdout and stderr apart."""
    return CliRunner()
