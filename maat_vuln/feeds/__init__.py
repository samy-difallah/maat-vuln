"""Feeds: clients for the sources signals come from."""

from maat_vuln.feeds.http import (
    CONNECT_TIMEOUT,
    DEFAULT_CONCURRENCY,
    MAX_ATTEMPTS,
    MAX_DELAY,
    READ_TIMEOUT,
    USER_AGENT,
    FetchError,
    HttpClient,
)

__all__ = [
    "CONNECT_TIMEOUT",
    "DEFAULT_CONCURRENCY",
    "MAX_ATTEMPTS",
    "MAX_DELAY",
    "READ_TIMEOUT",
    "USER_AGENT",
    "FetchError",
    "HttpClient",
]
