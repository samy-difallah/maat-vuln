"""Tests for the CISA KEV catalog client."""

import json
from datetime import date
from pathlib import Path

import pytest

from maat_vuln.feeds import (
    KEV_FEED_NAME,
    KEV_FILENAME,
    KEV_URL,
    FetchError,
    HttpClient,
    fetch_kev,
    parse_kev,
)
from maat_vuln.models import KevSignal

# Trimmed copy of the real catalog: one entry per ransomware value.
CATALOG = (Path(__file__).parent / "kev.json").read_bytes()


async def test_fetch_returns_raw_catalog(respx_mock):
    """The catalog is kept byte for byte, with its version info."""
    respx_mock.get(KEV_URL).respond(200, content=CATALOG)
    async with HttpClient() as client:
        feed = await fetch_kev(client)
    assert feed.name == KEV_FEED_NAME
    assert feed.url == KEV_URL
    assert feed.filename == KEV_FILENAME
    assert feed.content == CATALOG
    assert feed.version == {
        "catalogVersion": "2026.10.21",
        "dateReleased": "2026-10-21T14:04:39.8983Z",
    }


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (404, b"not found"),
        (200, b"<html>maintenance</html>"),
        (200, b'{"catalogVersion": "2026.10.21"}'),
    ],
)
async def test_fetch_rejects_bad_answer(respx_mock, status, body):
    """An error status or a malformed catalog is never stored."""
    respx_mock.get(KEV_URL).respond(status, content=body)
    async with HttpClient() as client:
        with pytest.raises(FetchError):
            await fetch_kev(client)


def test_parse_maps_cves_to_signals():
    """Each entry becomes an in-KEV signal with its dates."""
    assert parse_kev(CATALOG) == {
        "CVE-2026-106931": KevSignal(
            in_kev=True,
            date_added=date(2026, 10, 20),
            due_date=date(2026, 10, 23),
            known_ransomware_campaign_use=False,
        ),
        "CVE-2026-59310": KevSignal(
            in_kev=True,
            date_added=date(2026, 8, 18),
            due_date=date(2026, 8, 21),
            known_ransomware_campaign_use=True,
        ),
    }


def test_parse_normalizes_ids_and_defaults_ransomware():
    """IDs are uppercased; a missing ransomware field means unknown."""
    entry = {
        "cveID": " cve-2024-0001 ",
        "dateAdded": "2024-01-02",
        "dueDate": "2024-01-23",
    }
    content = json.dumps(
        {
            "catalogVersion": "2024.01.02",
            "dateReleased": "2024-01-02T00:00:00.000Z",
            "vulnerabilities": [entry],
        }
    ).encode()
    signal = parse_kev(content)["CVE-2024-0001"]
    assert signal.known_ransomware_campaign_use is False
