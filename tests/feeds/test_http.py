"""Tests for the shared HTTP client."""

import asyncio
import random
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from maat_vuln.feeds import (
    CONNECT_TIMEOUT,
    MAX_ATTEMPTS,
    MAX_DELAY,
    READ_TIMEOUT,
    USER_AGENT,
    FetchError,
    HttpClient,
)

URL = "https://feed.example/data.json"
RETRY_IN = 20
# Margin for the time elapsed between building the header and reading it.
CLOCK_SLACK = 5


@pytest.fixture
def delays(monkeypatch):
    """Record backoff delays instead of sleeping; jitter at its maximum."""
    recorded = []

    async def fake_sleep(delay):
        recorded.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(random, "uniform", lambda low, high: high)
    return recorded


async def test_identifies_itself_with_timeouts(respx_mock):
    """Requests carry the User-Agent and explicit timeouts."""
    route = respx_mock.get(URL).respond(200, json={"ok": True})
    async with HttpClient() as client:
        response = await client.get(URL, params={"cve": "CVE-2024-0001"})
    assert response.json() == {"ok": True}
    request = route.calls.last.request
    assert request.headers["User-Agent"] == USER_AGENT
    assert request.url.params["cve"] == "CVE-2024-0001"
    timeout = request.extensions["timeout"]
    assert timeout["connect"] == CONNECT_TIMEOUT
    assert timeout["read"] == READ_TIMEOUT


async def test_client_error_returned_without_retry(respx_mock, delays):
    """A 404 is an answer, not a transient failure."""
    route = respx_mock.get(URL).respond(404)
    async with HttpClient() as client:
        response = await client.get(URL)
    assert response.status_code == httpx.codes.NOT_FOUND
    assert route.call_count == 1
    assert delays == []


async def test_server_error_retried_with_backoff(respx_mock, delays):
    """A 5xx is retried after an exponential backoff."""
    route = respx_mock.get(URL)
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(502),
        httpx.Response(200),
    ]
    async with HttpClient() as client:
        response = await client.get(URL)
    assert response.status_code == httpx.codes.OK
    assert delays == [0.5, 1.0]


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [
        ("5", 5.0),
        ("3600", MAX_DELAY),
        ("not a date", 0.5),
    ],
)
async def test_retry_after_seconds(respx_mock, delays, retry_after, expected):
    """A 429 waits as asked, capped, or backs off on an unreadable value."""
    route = respx_mock.get(URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": retry_after}),
        httpx.Response(200),
    ]
    async with HttpClient() as client:
        await client.get(URL)
    assert delays == [expected]


@pytest.mark.parametrize("zone", [UTC, None])
async def test_retry_after_http_date(respx_mock, delays, zone):
    """An HTTP-date Retry-After is turned into a delay from now."""
    later = datetime.now(UTC) + timedelta(seconds=RETRY_IN)
    header = format_datetime(later.replace(tzinfo=zone), usegmt=bool(zone))
    route = respx_mock.get(URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": header}),
        httpx.Response(200),
    ]
    async with HttpClient() as client:
        await client.get(URL)
    assert len(delays) == 1
    assert RETRY_IN - CLOCK_SLACK < delays[0] <= RETRY_IN


@pytest.mark.parametrize(
    "outcome",
    [httpx.ConnectTimeout("timed out"), httpx.Response(500)],
)
async def test_gives_up_after_max_attempts(respx_mock, delays, outcome):
    """A failure on every attempt raises FetchError, chained to it."""
    route = respx_mock.get(URL)
    route.side_effect = [outcome] * MAX_ATTEMPTS
    async with HttpClient() as client:
        with pytest.raises(FetchError) as caught:
            await client.get(URL)
    assert route.call_count == MAX_ATTEMPTS
    assert len(delays) == MAX_ATTEMPTS - 1
    assert isinstance(caught.value.__cause__, httpx.HTTPError)


async def test_concurrency_capped_per_host(respx_mock):
    """Each host gets its own cap, so one never blocks another."""
    in_flight = {"a.example": 0, "b.example": 0}
    peak = {"a.example": 0, "b.example": 0, "total": 0}

    async def slow(request):
        host = request.url.host
        in_flight[host] += 1
        peak[host] = max(peak[host], in_flight[host])
        peak["total"] = max(peak["total"], sum(in_flight.values()))
        await asyncio.sleep(0.01)
        in_flight[host] -= 1
        return httpx.Response(200)

    respx_mock.get(host__in=list(in_flight)).mock(side_effect=slow)
    urls = [f"https://{host}/x" for host in in_flight for _ in range(4)]
    async with HttpClient(concurrency=2) as client:
        await asyncio.gather(*(client.get(url) for url in urls))
    assert peak == {"a.example": 2, "b.example": 2, "total": 4}


def test_concurrency_must_be_positive():
    """A zero cap would block every request forever."""
    with pytest.raises(ValueError, match="concurrency"):
        HttpClient(concurrency=0)
