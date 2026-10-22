"""Tests for the Vulnerability-Lookup CVSS client."""

import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest

from maat_vuln.feeds import (
    CVSS_BATCH_SIZE,
    CVSS_LOOKUP_URL,
    MAX_ATTEMPTS,
    HttpClient,
    lookup_cvss,
)
from maat_vuln.models import CvssValue

# Trimmed copy of a real bulk answer for these CVEs.
ANSWER = json.loads((Path(__file__).parent / "cvss_bulk.json").read_text())
CVES = ["CVE-2016-0800", "CVE-2021-44228", "CVE-2024-3094", "CVE-2099-0001"]
LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def value(version, base_score, vector):
    """Build a CVSS value looked up in Vulnerability-Lookup."""
    return CvssValue(
        version=version,
        base_score=base_score,
        vector=vector,
        source="vulnerability-lookup",
    )


def no_record(request):
    """Answer every asked ID with no record."""
    ids = json.loads(request.content)["ids"]
    return httpx.Response(
        200, json={"data": [{"id": i, "vulnerability": None} for i in ids]}
    )


async def lookup(cves):
    """Look up the CVEs with a fresh client."""
    async with HttpClient() as client:
        return await lookup_cvss(client, cves)


async def test_lookup_reads_cve_and_nvd_records(respx_mock):
    """Values of both records are kept once each, CVE record first."""
    route = respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=ANSWER)
    entries = await lookup(reversed(CVES))
    assert json.loads(route.calls.last.request.content) == {
        "ids": [id_ for cve in CVES for id_ in (cve, "fkie_" + cve.lower())]
    }
    assert {entry.id: entry.values for entry in entries} == {
        "CVE-2016-0800": [
            value("3.0", 5.9, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            value("2.0", 4.3, "AV:N/AC:M/Au:N/C:P/I:N/A:N"),
        ],
        "CVE-2021-44228": [
            value("3.1", 10.0, LOG4SHELL),
            value("2.0", 9.3, "AV:N/AC:M/Au:N/C:C/I:C/A:C"),
        ],
        "CVE-2024-3094": [value("3.1", 10.0, LOG4SHELL)],
        "CVE-2099-0001": None,
    }
    assert len({entry.retrieved_at for entry in entries}) == 1


async def test_lookup_batches_cves(respx_mock):
    """CVEs are sent by batches the endpoint accepts."""
    route = respx_mock.post(CVSS_LOOKUP_URL).mock(side_effect=no_record)
    cves = [f"CVE-2024-{n:04d}" for n in range(CVSS_BATCH_SIZE + 1)]
    entries = await lookup(cves)
    assert [entry.id for entry in entries] == cves
    assert sorted(
        len(json.loads(call.request.content)["ids"]) for call in route.calls
    ) == [2, 2 * CVSS_BATCH_SIZE]


@pytest.mark.parametrize(
    "answer",
    [
        httpx.ConnectError("unreachable"),
        httpx.Response(400, json={"message": "invalid payload"}),
        httpx.Response(200, text="<html>maintenance</html>"),
    ],
    ids=["transport", "status", "not-json"],
)
async def test_failed_batch_left_out(respx_mock, monkeypatch, answer):
    """No CVE of a failed batch is in the result, to be retried later."""

    async def no_sleep(delay):
        """Skip the retry backoff."""

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    respx_mock.post(CVSS_LOOKUP_URL).mock(side_effect=[answer] * MAX_ATTEMPTS)
    assert await lookup(CVES) == []


async def test_unusable_cve_left_out_alone(respx_mock):
    """A CVE missing from the answer or with a bad record is left out."""
    data = copy.deepcopy(ANSWER["data"])
    del data[0]  # CVE-2016-0800
    data[3]["vulnerability"]["containers"]["cna"]["metrics"][0]["cvssV3_1"][
        "baseScore"
    ] = 11  # CVE-2024-3094
    respx_mock.post(CVSS_LOOKUP_URL).respond(200, json={"data": data})
    entries = await lookup(CVES)
    assert [entry.id for entry in entries] == [
        "CVE-2021-44228",
        "CVE-2099-0001",
    ]


async def test_no_cve_no_request(respx_mock):
    """Nothing to look up sends nothing."""
    route = respx_mock.post(CVSS_LOOKUP_URL)
    assert await lookup([]) == []
    assert not route.called
