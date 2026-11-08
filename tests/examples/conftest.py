"""Fixtures for the example tests: an isolated cache, a snapshot, no CVSS.

``kev.json`` and ``epss.csv`` are the real feeds of 2026-11-01, trimmed to
the CVEs of the examples.
"""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from maat_vuln.feeds import CVSS_LOOKUP_URL, EPSS_FILENAME, KEV_FILENAME
from maat_vuln.snapshot import RawFeed, create_snapshot, default_root

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    """Point the user cache to a temporary directory, never the real one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    # Wide enough for Rich never to wrap a table cell.
    monkeypatch.setenv("COLUMNS", "200")


@pytest.fixture(autouse=True)
def snapshot(cache):
    """Snapshot of the trimmed KEV and EPSS feeds in the user cache."""
    feeds = [
        ("kev", KEV_FILENAME, (FIXTURES / "kev.json").read_bytes()),
        (
            "epss",
            EPSS_FILENAME,
            gzip.compress((FIXTURES / "epss.csv").read_bytes()),
        ),
    ]
    return create_snapshot(
        [
            RawFeed(
                name=name,
                url=f"https://example.org/{filename}",
                filename=filename,
                retrieved_at=datetime(2026, 11, 1, 12, tzinfo=UTC),
                version={},
                content=content,
            )
            for name, filename, content in feeds
        ],
        root=default_root(),
    )


@pytest.fixture(autouse=True)
def no_cvss(respx_mock):
    """Answer every CVSS lookup with no result, so no test needs network."""

    def answer(request):
        ids = json.loads(request.content)["ids"]
        data = [{"id": id_, "vulnerability": None} for id_ in ids]
        return httpx.Response(200, json={"data": data})

    respx_mock.post(CVSS_LOOKUP_URL).mock(side_effect=answer)


@pytest.fixture
def runner():
    """CLI runner keeping stdout and stderr apart."""
    return CliRunner()
