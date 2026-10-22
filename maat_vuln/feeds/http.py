"""Shared HTTP client for the feeds: identification, timeouts, retries.

One client is shared per run so connections are reused. A semaphore per
host caps simultaneous requests to one service, and transient failures
are retried with exponential backoff and jitter.
"""

import asyncio
import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from importlib.metadata import version
from types import TracebackType
from typing import Self

import httpx
from pydantic import JsonValue

USER_AGENT = f"maat-vuln/{version('maat-vuln')}"
DEFAULT_CONCURRENCY = 8
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
MAX_ATTEMPTS = 4
BACKOFF_BASE = 0.5
# Also caps Retry-After, so a server asking for an hour cannot stall a run.
MAX_DELAY = 30.0


class FetchError(Exception):
    """Request still failing after the last retry."""


def _is_retryable(response: httpx.Response) -> bool:
    """Tell whether a response is a transient failure worth retrying."""
    return (
        response.status_code == httpx.codes.TOO_MANY_REQUESTS
        or response.is_server_error
    )


def _retry_after(response: httpx.Response) -> float | None:
    """Return the delay asked by ``Retry-After``, in seconds, if any."""
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        date = parsedate_to_datetime(value)
    except ValueError:
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    return (date - datetime.now(UTC)).total_seconds()


class HttpClient:
    """Async HTTP client shared by every feed request of a run."""

    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY) -> None:
        """Create the client; ``concurrency`` caps requests per host."""
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self._concurrency = concurrency
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            follow_redirects=True,
        )

    async def __aenter__(self) -> Self:
        """Return the client, to be closed on exit."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the underlying connections."""
        await self._client.aclose()

    async def get(
        self, url: str, params: dict[str, str] | None = None
    ) -> httpx.Response:
        """Send a GET request, retrying transient failures.

        Raises:
            FetchError: the last attempt still failed.
        """
        return await self._send("GET", url, params=params)

    async def post(self, url: str, json: JsonValue) -> httpx.Response:
        """Send a POST request with a JSON body, retrying failures.

        Raises:
            FetchError: the last attempt still failed.
        """
        return await self._send("POST", url, json=json)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json: JsonValue = None,
    ) -> httpx.Response:
        """Send a request, retrying transient failures.

        Transport errors, HTTP 429 and 5xx are retried; any other
        response is returned as is, for the caller to interpret.

        Raises:
            FetchError: the last attempt still failed.
        """
        semaphore = self._semaphores.setdefault(
            httpx.URL(url).host, asyncio.Semaphore(self._concurrency)
        )
        failure: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            asked = None
            try:
                # Released before sleeping, so a backoff blocks no one.
                async with semaphore:
                    response = await self._client.request(
                        method, url, params=params, json=json
                    )
            except httpx.TransportError as error:
                failure = error
            else:
                if not _is_retryable(response):
                    return response
                failure = httpx.HTTPStatusError(
                    f"HTTP {response.status_code} from {url}",
                    request=response.request,
                    response=response,
                )
                asked = _retry_after(response)
            if attempt + 1 < MAX_ATTEMPTS:
                backoff = random.uniform(0, BACKOFF_BASE * 2**attempt)
                await asyncio.sleep(min(MAX_DELAY, max(backoff, asked or 0)))
        raise FetchError(
            f"{url} still failing after {MAX_ATTEMPTS} attempts"
        ) from failure
