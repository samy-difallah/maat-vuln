"""Tests for the FIRST EPSS scores client."""

import gzip
from datetime import date
from pathlib import Path

import pytest

from maat_vuln.feeds import (
    EPSS_FEED_NAME,
    EPSS_FILENAME,
    EPSS_URL,
    FetchError,
    HttpClient,
    fetch_epss,
    parse_epss,
)
from maat_vuln.models import EpssSignal

# Trimmed copy of the real file, gzipped as it is served.
SCORES = gzip.compress((Path(__file__).parent / "epss.csv").read_bytes())
HEADER = "#model_version:v2026.06.15,score_date:2026-10-22T12:00:12Z\n"


def scores(text: str) -> bytes:
    """Return a gzipped score file with the given text."""
    return gzip.compress(text.encode())


async def test_fetch_returns_raw_scores(respx_mock):
    """The gzipped file is kept byte for byte, with its version info."""
    respx_mock.get(EPSS_URL).respond(200, content=SCORES)
    async with HttpClient() as client:
        feed = await fetch_epss(client)
    assert feed.name == EPSS_FEED_NAME
    assert feed.url == EPSS_URL
    assert feed.filename == EPSS_FILENAME
    assert feed.content == SCORES
    assert feed.version == {
        "model_version": "v2026.06.15",
        "score_date": "2026-10-22T12:00:12Z",
    }


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (404, b"not found"),
        (200, b"<html>maintenance</html>"),
        (200, scores("cve,epss,percentile\nCVE-2024-0001,0.1,0.5\n")),
        (200, scores("#model_version:v2026.06.15\ncve,epss,percentile\n")),
        (200, scores(HEADER + "cve,percentile,epss\n")),
        (200, scores(HEADER + "cve,epss,percentile\nCVE-2024-0001,2,0.5\n")),
        (200, SCORES[:-8]),
    ],
    ids=[
        "status",
        "not-gzip",
        "no-comment",
        "no-score-date",
        "columns",
        "probability",
        "truncated",
    ],
)
async def test_fetch_rejects_bad_answer(respx_mock, status, body):
    """An error status or a malformed file is never stored."""
    respx_mock.get(EPSS_URL).respond(status, content=body)
    async with HttpClient() as client:
        with pytest.raises(FetchError):
            await fetch_epss(client)


def test_parse_maps_asked_cves_to_signals():
    """Only the asked CVEs that are scored get a signal."""
    assert parse_epss(SCORES, ["CVE-2021-44228", "CVE-2099-0001"]) == {
        "CVE-2021-44228": EpssSignal(
            probability=0.99999,
            percentile=1.0,
            model_version="v2026.06.15",
            score_date=date(2026, 10, 22),
        ),
    }


def test_parse_normalizes_ids_and_score_date():
    """IDs are uppercased; the score date is the UTC day."""
    content = scores(
        "#model_version:v2026.06.15,score_date:2026-10-23T01:00:00+02:00\n"
        "cve,epss,percentile\n"
        "cve-2024-0001,0.1,0.5\n"
    )
    signal = parse_epss(content, ["CVE-2024-0001"])["CVE-2024-0001"]
    assert signal.score_date == date(2026, 10, 22)
